// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <sys/random.h>

#define STACK_SIZE (1024 * 1024)

void *map_elf(const char *filename)
{
	struct stat st;
	void *mapped_file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	mapped_file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapped_file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return mapped_file;
}

static uintptr_t find_pie_map_size(Elf64_Phdr *program_headers, int num_headers, uintptr_t pg_size)
{
	uintptr_t max_vaddr_end = 0;

	for (int i = 0; i < num_headers; i++) {
		Elf64_Phdr *current_header = &program_headers[i];

		if (current_header->p_type == PT_LOAD) {
			uintptr_t segment_end = current_header->p_vaddr + current_header->p_memsz;

			if (segment_end > max_vaddr_end)
				max_vaddr_end = segment_end;
		}
	}

	max_vaddr_end = (max_vaddr_end + pg_size - 1) & ~(pg_size - 1);
	if (max_vaddr_end == 0)
		max_vaddr_end = pg_size;

	return max_vaddr_end;
}


void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	void *file_buffer = map_elf(filename);

	Elf64_Ehdr *elf_header = (Elf64_Ehdr *)file_buffer;

	if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}
	if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	uintptr_t base_address = 0;
	Elf64_Phdr *program_headers = (Elf64_Phdr *)((char *)file_buffer + elf_header->e_phoff);
	uintptr_t pg_size = sysconf(_SC_PAGE_SIZE);

	if (elf_header->e_type == ET_DYN) {
		uintptr_t total_pie_size = find_pie_map_size(program_headers, elf_header->e_phnum, pg_size);

		void *random_base = mmap(NULL, total_pie_size, PROT_NONE,
							   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (random_base == MAP_FAILED) {
			perror("mmap load_base");
			exit(8);
		}
		munmap(random_base, total_pie_size);
		base_address = (uintptr_t)random_base;
	}

	Elf64_Phdr *phdr_location_ptr = NULL;

	for (int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *current_header = &program_headers[i];

		if (current_header->p_type == PT_PHDR)
			phdr_location_ptr = current_header;

		if (current_header->p_type == PT_LOAD) {
			uintptr_t virtual_addr = current_header->p_vaddr + base_address;
			uintptr_t aligned_vaddr = virtual_addr & ~(pg_size - 1);
			uintptr_t vaddr_offset = virtual_addr - aligned_vaddr;
			size_t segment_map_len = current_header->p_memsz + vaddr_offset;

			void *mapped_segment_ptr = mmap((void *)aligned_vaddr,
							   segment_map_len,
							   PROT_READ | PROT_WRITE,
							   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
							   -1, 0);
			if (mapped_segment_ptr == MAP_FAILED) {
				perror("mmap PT_LOAD");
				exit(5);
			}

			memcpy((void *)virtual_addr,
				   (char *)file_buffer + current_header->p_offset,
				   current_header->p_filesz);

			int segment_perms = 0;

			if (current_header->p_flags & PF_R)
				segment_perms |= PROT_READ;
			if (current_header->p_flags & PF_W)
				segment_perms |= PROT_WRITE;
			if (current_header->p_flags & PF_X)
				segment_perms |= PROT_EXEC;

			if (mprotect(mapped_segment_ptr, segment_map_len, segment_perms) == -1) {
				perror("mprotect");
				exit(7);
			}
		}
	}

	void *new_stack_base = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (new_stack_base == MAP_FAILED) {
		perror("mmap stack");
		exit(6);
	}

	char *stack_ptr = (char *)new_stack_base + STACK_SIZE;

	int env_var_count = 0;

	while (envp[env_var_count] != NULL)
		env_var_count++;

	char *stack_argv_ptrs[argc + 1];
	char *stack_envp_ptrs[env_var_count + 1];

	for (int i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]) + 1;

		stack_ptr -= len;
		memcpy(stack_ptr, argv[i], len);
		stack_argv_ptrs[i] = stack_ptr;
	}
	stack_argv_ptrs[argc] = NULL;

	for (int i = 0; i < env_var_count; i++) {
		size_t len = strlen(envp[i]) + 1;

		stack_ptr -= len;
		memcpy(stack_ptr, envp[i], len);
		stack_envp_ptrs[i] = stack_ptr;
	}
	stack_envp_ptrs[env_var_count] = NULL;

	stack_ptr -= 16;
	void *random_data_on_stack = stack_ptr;

	getrandom(random_data_on_stack, 16, 0);

	stack_ptr = (char *)((uintptr_t)stack_ptr & ~15);

	Elf64_auxv_t *aux_ptr = (Elf64_auxv_t *)stack_ptr;

	aux_ptr--;
	aux_ptr->a_type = AT_NULL;
	aux_ptr->a_un.a_val = 0;

	aux_ptr--;
	aux_ptr->a_type = AT_RANDOM;
	aux_ptr->a_un.a_val = (uintptr_t)random_data_on_stack;

	if (phdr_location_ptr != NULL) {
		aux_ptr--;
		aux_ptr->a_type = AT_PHDR;
		aux_ptr->a_un.a_val = phdr_location_ptr->p_vaddr + base_address;
	}

	aux_ptr--;
	aux_ptr->a_type = AT_PHENT;
	aux_ptr->a_un.a_val = elf_header->e_phentsize;

	aux_ptr--;
	aux_ptr->a_type = AT_PHNUM;
	aux_ptr->a_un.a_val = elf_header->e_phnum;

	aux_ptr--;
	aux_ptr->a_type = AT_PAGESZ;
	aux_ptr->a_un.a_val = pg_size;

	aux_ptr--;
	aux_ptr->a_type = AT_ENTRY;
	aux_ptr->a_un.a_val = elf_header->e_entry + base_address;

	stack_ptr = (char *)aux_ptr;

	stack_ptr -= (env_var_count + 1) * sizeof(char *);
	memcpy(stack_ptr, stack_envp_ptrs, (env_var_count + 1) * sizeof(char *));

	stack_ptr -= (argc + 1) * sizeof(char *);
	memcpy(stack_ptr, stack_argv_ptrs, (argc + 1) * sizeof(char *));

	stack_ptr -= sizeof(uint64_t);
	*(uint64_t *)stack_ptr = (uint64_t)argc;


	void (*entry_point)() = (void (*)())(elf_header->e_entry + base_address);

	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(stack_ptr), "r"(entry_point)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
