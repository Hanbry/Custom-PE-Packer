#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define KEY_LENGTH 16 // 128 bits

void encrypt_RC4(unsigned char *buf, size_t file_size, unsigned char *key) {
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, KEY_LENGTH, key);
    RC4(&rc4_key, file_size, buf, buf);
}

void encrypt_XOR(unsigned char *buf, size_t file_size, unsigned char *key) {
    for (size_t i = 0; i < file_size; i++) {
        buf[i] ^= key[i % KEY_LENGTH];
    }
}

// Generate random 128-Bit Key
void generate_random_key(unsigned char* key, unsigned char* elf_buf) {
    // Hash the ELF buffer to generate a random seed
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    EVP_DigestUpdate(mdctx, elf_buf, strlen(elf_buf));

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_destroy(mdctx);

    // Seed the random number generator with the hash
    RAND_seed(hash, hash_len);

    // Generate random bytes for the key
    RAND_bytes(key, KEY_LENGTH);
}


int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <input ELF file> <output ELF file> <encryption key>\n", argv[0]);
        return 1;
    }

    FILE *input_fd = fopen(argv[1], "r");
    if (input_fd == NULL) {
        perror("Failed to open input ELF file");
        return 1;
    }

    FILE *output_fd = fopen(argv[2], "w+");
    if (output_fd < 0) {
        perror("Failed to open output ELF file");
        fclose(input_fd);
        return 1;
    }

    // Get the size of the ELF file
    fseek(input_fd, 0, SEEK_END);
    size_t file_size = ftell(input_fd);
    rewind(input_fd);
    
    // Read the ELF file into memory
    unsigned char *elf_buf = malloc(file_size);
    size_t bytes_read = fread(elf_buf, 1, file_size, input_fd);
    if (bytes_read < file_size) {
        perror("Failed to read ELF file");
        free(elf_buf);
        fclose(input_fd);
        return 1;
    }

    fclose(input_fd);

    // Generate random key
    unsigned char key[KEY_LENGTH];
    generate_random_key(key, elf_buf);

    // Print random key
    printf("Use following key to decrypt: ");
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Encrypt the ELF file
    encrypt_RC4(elf_buf, file_size, key);
    encrypt_XOR(elf_buf, file_size, key);

    // Write the encrypted ELF file to the output file
    fwrite(elf_buf, file_size, 1, output_fd);

    // Close output file descriptors
    fclose(output_fd);

    // Free elf buffer
    free(elf_buf);

    return 0;
}
