// per_registry.cpp
#include <windows.h>
#include <cstring>

int main() {
    // Registry key details
    HKEY hKey;
    const char* subKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "MyPersistentApp";  // Name of the registry entry
    const char* exePath = "C:\\Users\\i_rajesh.chandrappa\\Downloads\\message.exe";

    // Open or create the registry key for current user run keys with write access
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        result = RegCreateKeyExA(HKEY_CURRENT_USER, subKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
        if (result != ERROR_SUCCESS)
            return 1; // Fail silently
    }

    // Set the registry value to the executable path for automatic launch
    result = RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)exePath, (DWORD)(strlen(exePath) + 1));
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS) ? 0 : 1;
}
