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

#define STACK_SIZE (1024 * 1024) // 1MB pentru stivă

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

/**
 * Functie ajutatoare pentru a calcula marimea totala de care are nevoie
 * un binar PIE pentru a fi mapat.
 * Parcurge headerele si gaseste adresa virtuala maxima.
 */
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

	// Aliniem la pagina următoare
	max_vaddr_end = (max_vaddr_end + pg_size - 1) & ~(pg_size - 1);
	if (max_vaddr_end == 0)
		max_vaddr_end = pg_size; // Asigurăm minim o pagină

	return max_vaddr_end;
}


void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	void *file_buffer = map_elf(filename);

	// Task 1: Validarea
	// Prima data, verificam daca e un fisier ELF valid.
	Elf64_Ehdr *elf_header = (Elf64_Ehdr *)file_buffer;

	if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}
	if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	// Task 5: Determinăm adresa de bază (pentru PIE)
	uintptr_t base_address = 0;
	Elf64_Phdr *program_headers = (Elf64_Phdr *)((char *)file_buffer + elf_header->e_phoff);
	uintptr_t pg_size = sysconf(_SC_PAGE_SIZE);

	// Daca e ET_DYN (PIE), trebuie sa gasim o adresa de baza aleatorie.
	if (elf_header->e_type == ET_DYN) {
		// 1. Calculam toata marimea de care are nevoie binarul
		uintptr_t total_pie_size = find_pie_map_size(program_headers, elf_header->e_phnum, pg_size);

		// 2. Cerem o adresa aleatorie de la kernel pentru aceasta marime
		void *random_base = mmap(NULL, total_pie_size, PROT_NONE,
							   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (random_base == MAP_FAILED) {
			perror("mmap load_base");
			exit(8);
		}
		// 3. Eliberăm adresa si o pastram ca adresa noastra de baza
		munmap(random_base, total_pie_size);
		base_address = (uintptr_t)random_base;
	}


	// Task 2, 3 & 5: Încărcarea segmentelor
	// Acum parcurgem header-ele de program sa incarcam segmentele
	Elf64_Phdr *phdr_location_ptr = NULL; // Pointer la PT_PHDR, necesar pentru auxv

	for (int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *current_header = &program_headers[i];

		// Task 4: Salvăm locatia PT_PHDR pentru a o pune pe stiva (in auxv)
		if (current_header->p_type == PT_PHDR)
			phdr_location_ptr = current_header;

		// Incarcam doar segmentele de tip "PT_LOAD"
		if (current_header->p_type == PT_LOAD) {
			// 1. Calculam adresele, aliniate la pagina
			uintptr_t virtual_addr = current_header->p_vaddr + base_address;
			uintptr_t aligned_vaddr = virtual_addr & ~(pg_size - 1);
			uintptr_t vaddr_offset = virtual_addr - aligned_vaddr;
			size_t segment_map_len = current_header->p_memsz + vaddr_offset;

			// Task 3: Mapam memoria intai cu drept de scriere (Write)
			void *mapped_segment_ptr = mmap((void *)aligned_vaddr,
							   segment_map_len,
							   PROT_READ | PROT_WRITE, // Permisiuni temporare: RW
							   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
							   -1, 0);
			if (mapped_segment_ptr == MAP_FAILED) {
				perror("mmap PT_LOAD");
				exit(5);
			}

			// 3. Copiem datele din fisierul ELF in memoria mapata
			memcpy((void *)virtual_addr,
				   (char *)file_buffer + current_header->p_offset,
				   current_header->p_filesz); // Copiem doar p_filesz!

			// Task 3: Setam permisiunile finale (R, W, X)
			int segment_perms = 0;

			if (current_header->p_flags & PF_R)
				segment_perms |= PROT_READ;
			if (current_header->p_flags & PF_W)
				segment_perms |= PROT_WRITE;
			if (current_header->p_flags & PF_X)
				segment_perms |= PROT_EXEC;

			// Folosim mprotect pentru a seta permisiunile corecte
			if (mprotect(mapped_segment_ptr, segment_map_len, segment_perms) == -1) {
				perror("mprotect");
				exit(7);
			}
		}
	}


	// Task 4: Construim stiva (stack-ul)
	// Alocam o noua zona de memorie pentru stiva
	void *new_stack_base = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (new_stack_base == MAP_FAILED) {
		perror("mmap stack");
		exit(6);
	}

	// Incepem de la adresa cea mai mare (stiva creste in jos)
	char *stack_ptr = (char *)new_stack_base + STACK_SIZE;

	// a. Copiem string-urile pentru argv si envp pe stiva
	int env_var_count = 0;

	// Numaram cate variabile de mediu avem
	while (envp[env_var_count] != NULL)
		env_var_count++;

	// Array-uri temporare pentru a tine minte pointerii la string-urile de pe stiva
	char *stack_argv_ptrs[argc + 1];
	char *stack_envp_ptrs[env_var_count + 1];

	for (int i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]) + 1; // +1 pentru '\0'

		stack_ptr -= len; // Facem loc pe stiva
		memcpy(stack_ptr, argv[i], len); // Copiem string-ul
		stack_argv_ptrs[i] = stack_ptr; // Salvam pointer-ul
	}
	stack_argv_ptrs[argc] = NULL; // Terminatorul listei argv

	for (int i = 0; i < env_var_count; i++) {
		size_t len = strlen(envp[i]) + 1;

		stack_ptr -= len;
		memcpy(stack_ptr, envp[i], len);
		stack_envp_ptrs[i] = stack_ptr;
	}
	stack_envp_ptrs[env_var_count] = NULL; // Terminatorul listei envp

	// b. AT_RANDOM data (16 octeti de date aleatorii)
	stack_ptr -= 16;
	void *random_data_on_stack = stack_ptr;

	getrandom(random_data_on_stack, 16, 0);

	// c. Aliniere la 16 octeti (cerinta ABI)
	stack_ptr = (char *)((uintptr_t)stack_ptr & ~15);

	// d. Punem vectorul auxiliar (auxv) pe stiva (in ordine inversa)
	Elf64_auxv_t *aux_ptr = (Elf64_auxv_t *)stack_ptr;

	aux_ptr--; // Mergem in jos pe stiva
	aux_ptr->a_type = AT_NULL; // Terminatorul auxv
	aux_ptr->a_un.a_val = 0;

	aux_ptr--;
	aux_ptr->a_type = AT_RANDOM;
	aux_ptr->a_un.a_val = (uintptr_t)random_data_on_stack;

	// Binarele 'nolibc' nu au PT_PHDR, dar cele cu 'libc' au nevoie de el.
	if (phdr_location_ptr != NULL) {
		aux_ptr--;
		aux_ptr->a_type = AT_PHDR;
		aux_ptr->a_un.a_val = phdr_location_ptr->p_vaddr + base_address; // Adresa ajustata
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
	aux_ptr->a_un.a_val = elf_header->e_entry + base_address; // Adresa ajustata

	stack_ptr = (char *)aux_ptr; // Actualizăm stack pointer-ul

	// e. Punem lista de pointeri envp pe stiva
	stack_ptr -= (env_var_count + 1) * sizeof(char *);
	memcpy(stack_ptr, stack_envp_ptrs, (env_var_count + 1) * sizeof(char *));

	// f. Punem lista de pointeri argv pe stiva
	stack_ptr -= (argc + 1) * sizeof(char *);
	memcpy(stack_ptr, stack_argv_ptrs, (argc + 1) * sizeof(char *));

	// g. Punem argc (numarul de argumente) pe stiva
	stack_ptr -= sizeof(uint64_t);
	*(uint64_t *)stack_ptr = (uint64_t)argc;

	// Acum stack_ptr arata exact unde trebuie (la argc)


	// TODO: Set the entry point and the stack pointer
	// Task 4 & 5: Setam adresa de intrare finala (ajustata cu adresa de baza)
	void (*entry_point)() = (void (*)())(elf_header->e_entry + base_address);

	// Transferam controlul
	__asm__ __volatile__(
			"mov %0, %%rsp\n"	// Setam noul stack pointer
			"xor %%rbp, %%rbp\n"	// Curatam base pointer-ul
			"jmp *%1\n"			// Sarim la entry point-ul ELF-ului
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
