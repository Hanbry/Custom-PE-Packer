#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>


unsigned int load_elf(void* elf_buf, unsigned int size) {
    Elf64_Ehdr      *elf_header = NULL;
    Elf64_Phdr      *phdr       = NULL;
    Elf64_Shdr      *shdr       = NULL;
    char            *start      = NULL;
    char            *taddr      = NULL;
    void            *entry      = NULL;
    int i = 0;
    char            *exec_mem   = NULL;

    elf_header = (Elf64_Ehdr *)elf_buf;
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        
        printf("Not an ELF file.\n");
        return 1;
    }

    exec_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    memset(exec_mem, 0x0, size);

    if (exec_mem == MAP_FAILED)
    {
        printf("Failed to allocate memory. Error: %s\n", strerror(errno));
        return 1;
    }

    // Get pointer to program headers
    Elf64_Phdr *program_headers = malloc(elf_header->e_phnum * sizeof(Elf64_Phdr));
    lseek(fd, elf_header->e_phoff, SEEK_SET);
    if (read(fd, program_headers, elf_header->e_phnum * sizeof(Elf64_Phdr)) != elf_header->e_phnum * sizeof(Elf64_Phdr)) {
        printf("Failed to read program headers.\n");
        return 1;
    }

    // Iterate through program headers
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_headers[i].p_type == PT_LOAD) {
            // Allocate memory at the virtual address specified in the program header
            printf("Phdr Offset %x \nPhdr Type %x\nprogram_headers[i].p_vaddr %x\nprogram_headers[i].p_memsz %x\nprogram_headers[i].p_flags %x\n", program_headers[i].p_offset, program_headers[i].p_type, program_headers[i].p_vaddr, program_headers[i].p_memsz, program_headers[i].p_flags);
            void *segment_memory = mmap((void *)program_headers[i].p_vaddr, program_headers[i].p_memsz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, program_headers[i].p_offset); */

            if (segment_memory == MAP_FAILED) {
                printf("Failed to allocate memory for program segment. Error: %s\n", strerror(errno));
                return 1;
            }

            // Zero out remaining memory
            memset(segment_memory + program_headers[i].p_filesz, 0, program_headers[i].p_memsz - program_headers[i].p_filesz);
            /*Set memory permissions
            if (mprotect(segment_memory, program_headers[i].p_memsz, program_headers[i].p_flags) < 0) {
                printf("Failed to set memory permissions.\n");
                return 1;
            }*/
        }
    }

    // Return entry point
    return elf_header->e_entry;
}

int main(int argc, char *argv[]) {

    // https://www.mgaillard.fr/2021/04/15/load-elf-user-mode.html

    if (argc < 2) {
        printf("Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }

    // Open the ELF file
    int fd = fopen(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("Failed to open file: %s\n", argv[1]);
        return 1;
    }

    // Allocate memory buffer for ELF file (1 Mebibyte)
    char elf_buf[1048576];
    memset(elf_buf, 0x0, sizeof(elf_buf));

    // Read ELF from file into buffer
    fread(elf_buf, sizeof(elf_buf), 1, fd);

    // Read and validate ELF header
    Elf64_Ehdr elf_header;
    if (read(fd, &elf_header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        printf("Failed to read ELF header.\n");
        return 1;
    }

    void (*entry_point)(void) = (void (*)(void))load_elf(elf_buf, sizeof(elf_buf));
    entry_point();

    // Clean up
    free(program_headers);
    close(fd);

    return 0;
}

