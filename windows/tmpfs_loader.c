#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PE-file>\n", argv[0]);
        return 1;
    }

    // Öffnen der Original-PE-Datei
    HANDLE input_fd = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    // Get size
    DWORD dwSize = GetFileSize(input_fd, NULL);

    // Read PE file into buffer
    unsigned char *pe_buf = malloc(dwSize);
    DWORD dwBytesRead = 0;
    ReadFile(input_fd, pe_buf, dwSize, dwBytesRead, NULL);
    // close the file handle
    CloseHandle(input_fd);

    

    // get the temp path
    TCHAR szTempPath[MAX_PATH];
    GetTempPath(MAX_PATH, szTempPath);

    // get a temp file name
    TCHAR szTempFile[MAX_PATH];
    GetTempFileName(szTempPath, "exe", 0, szTempFile);
    
    char ending[] = ".exe";
    char* final_path = lstrcat(szTempFile, ending);
    printf("modified Path %s\n", final_path);

    // create the file with FILE_FLAG_DELETE_ON_CLOSE and FILE_ATTRIBUTE_TEMPORARY
    HANDLE tmp_fd = CreateFile(final_path, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 
                              FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY, NULL);

    if (tmp_fd == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Failed to create file: %d\n"), GetLastError());
        return 1;
    }

    // write some data to the file
    DWORD dwBytesWritten;
    if (!WriteFile(tmp_fd, pe_buf, dwSize, &dwBytesWritten, NULL)) {
        printf("write failed\n");
    }

    printf("%d schould be %d\n", dwSize, dwBytesWritten);

    // since the file is created with FILE_FLAG_DELETE_ON_CLOSE, it will be deleted when the handle is closed
    printf("Temp file created at: %s\n", final_path);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(final_path, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
        DWORD errorCode = GetLastError();
        printf(("CreateProcess failed. Error code: %d\n"), errorCode);
        fclose(tmp_fd);
        return 1;
    }

    // Wait for termination of tmpfs-PE
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Free all ressources
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(tmp_fd);


    return 0;
}
