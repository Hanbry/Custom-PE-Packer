#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <elf.h> 

#define KEY_LENGTH 16  // 128 bits

// ELF-Headerstruktur
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

unsigned char key[KEY_LENGTH];

// Assembler-Code zum Entschlüsseln der ELF-Datei als Hexadezimalzeichenfolge
unsigned char decoder_stub[] = "\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC1\x00\x00\x00\x00\x48\x8A\x04\x18\x80\x34\x18\x00\x48\x87\x04\x18\x48\xFF\xC0\x49\xFF\xC1\x48\xFF\xC9\xEB\xF2";


//function to write key and key_size in the decoder stub
void set_key_in_decoder(size_t elf_size){
    // set key in decoder_stub
    memcpy(decoder_stub + 3, key, KEY_LENGTH);
    // set key_size in decoder_stub
    memcpy(decoder_stub + 11, &elf_size, sizeof(size_t));
}


// Generiert einen zufälligen 128-Bit-Schlüssel
void generate_random_key(unsigned char* key, FILE* elf_file) {
    // Seed den Zufallsgenerator mit der ELF-Datei
    fread(key, 1, KEY_LENGTH, elf_file);
    srand(time(NULL) ^ *(unsigned int*)key);

    // Generiere zufällige Bytes für den Schlüssel
    for (int i = 4; i < KEY_LENGTH; i++) {
        key[i] = rand();
    }

    // Schließe die ELF-Datei
    fclose(elf_file);
}

void xor_encrypt_elf(char* elf_data, size_t elf_size, char* key){
    // Verschlüssele die ELF-Datei mittels XOR
    size_t i;
    for(i = 0; i < elf_size; i++) {
        elf_data[i] ^= key[i % 128];
    }
}

// void aes_encrypt_elf(char* elf_data, size_t elf_size, char* key, unsigned char* encrypted_data)
// {
//     // Verschlüssele den ELF-Inhalt mit AES 128
//     AES_KEY aes_key;
//     AES_set_encrypt_key(key, 128, &aes_key);
//     AES_cbc_encrypt(elf_data, encrypted_data, elf_size, &aes_key, key, AES_ENCRYPT);
// }


int main(int argc, char* argv[]) {
    // Check if ELF-file has been provided
    if (argc < 2) {
        fprintf(stderr, "Please provide an ELF-File!\n");
        return 1;
    }

    // Read ELF-file
    FILE* elf_file = fopen(argv[1], "rb");
    if (!elf_file) {
        fprintf(stderr, "Couldn't open ELF-file!\n");
        return 1;
    }

    fseek(elf_file, 0, SEEK_END);
    size_t size = ftell(elf_file);
    fseek(elf_file, 0, SEEK_SET);

    char* elf = malloc(size);
    fread(elf, size, 1, elf_file);
    fclose(elf_file);

    // Generate random key
    unsigned char key[KEY_LENGTH];
    generate_random_key(key, elf_file);

    // Print random key
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Encode ELF-file

    // Allocate memory for encrypted file
    unsigned char* encrypted_data = (unsigned char*) malloc(size+sizeof(decoder_stub));

    //aes_encrypt_elf(elf, size, key, encrypted_data);
    xor_encrypt_elf(elf, size, key);

    // Write the encrypted ELF file and the decoder stub to a new ELF file
    FILE* output_file = fopen("encrypted.elf", "wb");

    fwrite(encrypted_data, size, 1, output_file);

    // Write decoderstub to encrypted file
    fwrite(decoder_stub, sizeof(decoder_stub), 1, output_file);

    fclose(output_file);

    free(encrypted_data);
    free(elf);

    return 0;
}