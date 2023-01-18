#include <stdio.h>
#include <Windows.h>


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PE file>",argv[0]);
        return 1;
    }

    // Laden der Original-PE-Datei in den Speicher
    HANDLE hFile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD dwSize = GetFileSize(hFile, NULL);
    LPVOID lpBuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    ReadFile(hFile, lpBuffer, dwSize, &dwSize, NULL);
    CloseHandle(hFile);

    // Einstellungen für die CreateProcess-Funktion
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
 
    // Ausführen der Original-PE-Datei im Speicher
    BOOL success = CreateProcess(NULL, lpBuffer, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    printf("Success: %d", success);

    // Aufräumen
    VirtualFree(lpBuffer, 0, MEM_RELEASE);
    return 0;
}


#include <Windows.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PE-file>\n", argv[0]);
        return 1;
    }

    // Einstellungen für die CreateProcess-Funktion
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Ausführen der Original-PE-Datei
    if (!CreateProcess(argv[1], NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DWORD errorCode = GetLastError();
        printf("CreateProcess failed. Error code: %d\n", errorCode);
        return 1;
    }

    // Warten auf das Ende des Prozesses
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}