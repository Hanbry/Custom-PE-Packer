#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int decrypt_elf(unsigned char *elf_buf, size_t file_size, unsigned char *key, size_t key_size) {
    // Decode XOR
    for (size_t i = 0; i < file_size; i++) {
        elf_buf[i] ^= key[i % key_size];
    }

    // Decode RC4
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, key_size, key);
    RC4(&rc4_key, file_size, elf_buf, elf_buf);

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("Usage: %s [PE File] [Key]\n", argv[0]);
        return 1;
    }

    // Open the PE file
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open file: %s\n", argv[1]);
        return 1;
    }

    // Get the size of the file
    DWORD dwFileSize = GetFileSize(hFile, NULL);

    // Allocate memory for the file
    LPVOID lpFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
    if (lpFileBuffer == NULL)
    {
        printf("Failed to allocate memory for file\n");
        CloseHandle(hFile);
        return 1;
    }

    // Read the file into memory
    DWORD dwBytesRead;
    if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &dwBytesRead, NULL))
    {
        printf("Failed to read file\n");
        VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }

    // Close the file handle
    CloseHandle(hFile);

    // Create a new process with the memory buffer
    DWORD dwBytesWritten;
    HANDLE hProcess = CreateProcessA(NULL, (LPSTR)lpFileBuffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, NULL, NULL);
    if (hProcess == NULL)
    {
        printf("Failed to create process\n");
        VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
        return 1;
    }

    // Resume the main thread of the new process
    ResumeThread(hProcess.hThread);

    // Wait for the new process to finish
    WaitForSingleObject(hProcess, INFINITE);

    // Release memory
    VirtualFree(lpFileBuffer, 0, MEM_RELEASE);

    return 0;
}
