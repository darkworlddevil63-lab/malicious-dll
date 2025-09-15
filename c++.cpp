#include <windows.h>

int main() {
    // PowerShell command line as wide string (can be changed as needed)
    LPCWSTR powershellPath = L"powershell.exe";
    LPCWSTR params = L"-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command \"Get-Date\"";

    SHELLEXECUTEINFOW shExecInfo = {0};
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = L"runas";  // Specifies to run as admin
    shExecInfo.lpFile = powershellPath;
    shExecInfo.lpParameters = params;
    shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_HIDE;    // Hide the window
    shExecInfo.hInstApp = NULL;

    if (!ShellExecuteExW(&shExecInfo)) {
        DWORD err = GetLastError();
        // Error handling if elevation fails or user cancels UAC prompt
        return 1;
    }

    // Optional: wait for process to complete
    WaitForSingleObject(shExecInfo.hProcess, INFINITE);

    CloseHandle(shExecInfo.hProcess);

    return 0;
}
