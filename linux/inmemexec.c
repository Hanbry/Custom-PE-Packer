#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <openssl/rc4.h>
#include <string.h>
#include <ctype.h>

#define KEY_LENGTH 16 // 128 bits

int decrypt_elf(unsigned char *elf_buf, size_t file_size, unsigned char *key) {
    // Decode XOR
    for (size_t i = 0; i < file_size; i++) {
        elf_buf[i] ^= key[i % KEY_LENGTH];
    }

    // Decode RC4
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, KEY_LENGTH, key);
    RC4(&rc4_key, file_size, elf_buf, elf_buf);

    return 0;
}


int main(int argc, char *argv[], char *envp[]) {

    if (argc < 3) {
        printf("Usage: %s <ELF file> <key>\n", argv[0]);
        return 1;
    }

    FILE *elf_fd = fopen(argv[1], "r");
    if (elf_fd == NULL) {
        perror("Failed to fopen ELF file");
        return 1;
    }

    // Create a new file in memory and get a file descriptor for it
    int mem_fd = memfd_create("elf_file", 0);
    if (mem_fd < 0) {
        perror("Failed to create file in memory");
        fclose(elf_fd);
        return 1;
    }

    // Get the size of the ELF file
    fseek(elf_fd, 0, SEEK_END);
    size_t file_size = ftell(elf_fd);
    rewind(elf_fd);

    // Read the ELF file into memory
    unsigned char *elf_buf = malloc(file_size);
    size_t bytes_read = fread(elf_buf, 1, file_size, elf_fd);
    if (bytes_read < file_size) {
        perror("Failed to read ELF file");
        free(elf_buf);
        fclose(elf_fd);
        return 1;
    }   

    // Get key from input and decode to byte array
    const char *hexstring = argv[2];
    const char *pos = hexstring;
    unsigned char key[KEY_LENGTH];

    for (size_t count = 0; count < sizeof key/sizeof *key; count++) {
        sscanf(pos, "%2hhx", &key[count]);
        pos += 2;
    }

    // Decrypt the ELF file
    int ret = decrypt_elf(elf_buf, file_size, key);
    if (ret != 0) {
        perror("Failed to decrypt ELF file");
        free(elf_buf);
        fclose(elf_fd);
        close(mem_fd);
        return 1;
    }

    write(mem_fd, elf_buf, file_size);

    // Close the file descriptor for the ELF file
    fclose(elf_fd);

    // Execute the ELF file in memory
    fexecve(mem_fd, argv, envp);

    // Free buf memory
    free(elf_buf);

    // Close the file descriptor for the memory file
    close(mem_fd);

    return 0;
}
