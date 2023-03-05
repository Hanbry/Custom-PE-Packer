#include <stdio.h>
#include <stdlib.h>
//#include <winnt.h>
#include <windows.h>
//#include <openssl/rc4.h>

#define KEY_LENGTH 16 // 128 bits

// Declarations
void* load_PE (char* PE_data);
int decrypt_elf(unsigned char *elf_buf, size_t file_size, unsigned char *key, size_t key_size);

int main(int argc, char** argv) {
     if (argc < 3) {
        printf("Usage: %s [PE File] [Key]\n", argv[0]);
        return 1;
    }

    FILE* exe_file = fopen(argv[1], "rb");
    if (exe_file == NULL) {
        perror("Failed to fopen PE file");
        return 1;
    }


    // Get file size
    fseek(exe_file, 0L, SEEK_END);
    long int file_size = ftell(exe_file);
    fseek(exe_file, 0L, SEEK_SET);

    // Allocate memory and read the whole file
    char* pe_buf = malloc(file_size+1);

    // Read file
    size_t n_read = fread(pe_buf, 1, file_size, exe_file);
    if(n_read != file_size) {
        printf("reading error (%d)\n", n_read);
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

    decrypt_PE(pe_buf, file_size, key);

    // Load the PE into memory
    void* start_address = load_PE(pe_buf);
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

    char* image_base = (char*)VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(image_base == NULL) return NULL; // allocation didn't work

    // COPY HEADERS TO MEMORY
    memcpy(image_base, PE_data, size_of_headers);

    // Copy PE section wise into memory
    for(int i = 0; i < num_of_sections; ++i) {
        // calculate the Virtual Address we need to copy the content, from the Relative Virtual Address 
        // section[i].VirtualAddress is a Relative Virtual Address
        char* dest_addr = image_base + sections[i].VirtualAddress;
        DWORD raw_data_size = sections[i].SizeOfRawData;

        // check if there is raw data to copy
        if(raw_data_size > 0) {
            // We copy SizeOfRawData bytes, from the offset PointerToRawData in the file
            memcpy(dest_addr, PE_data + sections[i].PointerToRawData, raw_data_size);
        } else {
            memset(dest_addr, 0, sections[i].Misc.VirtualSize);
        }
    }

    // IMPORT TABLE
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;

    // load the address of the import descriptors array
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // this array is null terminated
    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {

        // Get the name of the dll, and import it
        char* module_name = image_base + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA(module_name);
        
        if (import_module == NULL) return NULL;

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
                function_handle = (void *)GetProcAddress(import_module, (LPSTR)lookup_addr);
            }

            if (function_handle == NULL) return NULL;

            // change the IAT, and put the function address inside.
            address_table[i].u1.Function = (DWORD)function_handle;
        }
    }

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



// =============== DEOBFUSCATION HERE ================

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
    // Decode XOR
    for (size_t i = 0; i < file_size; i++) {
        pe_buf[i] ^= key[i % KEY_LENGTH];
    }

    unsigned char s[256];
    rc4_init(s, key);
    rc4_crypt(s, pe_buf, file_size);

    return 0;
}