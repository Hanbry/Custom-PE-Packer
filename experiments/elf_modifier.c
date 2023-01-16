#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s <elf_file> <decoder_stub> <encrypted_text>\n", argv[0]);
        return 1;
    }

    // Open the ELF file
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Get the size of the file
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return 1;
    }

    // Map the file into memory
    void *elf_data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_data == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Get the ELF header
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_data;

    // Get the offset and size of the text section
    Elf32_Shdr *shdr = (Elf32_Shdr *)(elf_data + ehdr->e_shoff);
    Elf32_Shdr *text_shdr = NULL;
    size_t text_offset = 0;
    size_t text_size = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_PROGBITS && strcmp(".text", (char *)(elf_data + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name)) == 0) {
            text_shdr = &shdr[i];
            text_offset = text_shdr->sh_offset;
            text_size = text_shdr->sh_size;
            break;
        }
    }

    if (text_shdr == NULL) {
        printf("Could not find the .text section\n");
        return 1;
    }

    // Open the decoder stub and the encrypted text
    int decoder_fd = open(argv[2], O_RDONLY);
    if (decoder_fd < 0) {
        perror("open decoder stub");
        return 1;
    }
    int encrypted_fd = open(argv[3], O_RDONLY);
    if (encrypted_fd < 0) {
        perror("open encrypted text");
        return 1;
    }

    // Get the size of the decoder stub and the encrypted text
    struct stat decoder_st;
    if (fstat(decoder_fd, &decoder_st) < 0) {
        perror("fstat decoder stub");
        return 1;
    }
    struct stat encrypted_st;
    if (fstat(encrypted_fd, &encrypted_st) < 0) {
        perror("fstat encrypted text");
        return 1;
    }

    // Make sure there is enough space in the text section
    if (text_size + decoder_st.st_size + encrypted_st.st_size > text_shdr->sh_size) {
        printf("Not enough space in the .text section\n");
        return 1;
    }

    // Move the original text data to make room for the decoder stub
    memmove((void *)(elf_data + text_offset + decoder_st.st_size), (void *)(elf_data + text_offset), text_size);

    // Read the decoder stub and the encrypted text into memory
    void *decoder_data = malloc(decoder_st.st_size);
    read(decoder_fd, decoder_data, decoder_st.st_size);
    void *encrypted_data = malloc(encrypted_st.st_size);
    read(encrypted_fd, encrypted_data, encrypted_st.st_size);

    // Insert the decoder stub and the encrypted text into the text section
    void *decoder_dest = elf_data + text_offset;
    void *elf_dest = decoder_dest + decoder_st.st_size
    memcpy(decoder_dest, decoder_data, decoder_st.st_size);
    memcpy(elf_dest, encrypted_data, encrypted_st.st_size);

    // Updating the size of text section to include decoder_stub and encrypted data
    text_shdr->sh_size = decoder_st.st_size + text_size + encrypted_st.st_size;

    // Update the program header's entry-point to the address of decoder_stub
    ehdr->e_entry = text_shdr->sh_addr;
    Elf32_Phdr* phdr = (Elf32_Phdr*)(elf_data + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD) {
            phdr[i].p_vaddr = text_shdr->sh_addr;
            break;
        }
    }
    // Cleanup and Exit
    munmap(elf_data, st.st_size);
    close(decoder_fd);
    close(encrypted_fd);
    close(fd);
    return 0;
}










void *text_dest = elf_data + text_offset;
memcpy(text_dest, encrypted_text, text_size);


