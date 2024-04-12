# Windows syscall tools

**syscall_dumper:** dumps the sycalls of the Windows OS in which the tool is executed.

**syscall_finder:** gets the sycall name if syscall id is provided and vice versa. This can be used in conjunction with other scripts to resolve syscall ids/names as needed.



> Note: In x64 Windows OS, syscalls are present in `\system32\ntdll.dll` and `\system32\win32u.dll`. So, syscalls present in these dlls are extracted. The x86 variants of these dlls doesn't contains syscalls as these are forwarded to wow64emulation layer.



## syscall_dumper:

Dumps syscalls to console. You can pipe the output to a file by `syscall_dumper.py > syscalls.txt`

Example:

```cmd
C:\Users\ElNino\Desktop\syscall_tools>syscall_dumper.py
OS Info:
[Windows 10] ver. 10.0.19044

syscalls found in ntdll.dll (C:\Windows\System32\ntdll.dll):

 Fun   |  entry   |  file   | syscall | function name
 Ord   |  RVA     |  offset | id      |
 ----- | -------  | ------- |-------  | -----------------------------------
 0xc8  | 0x9d0a0  | 0x9c4a0 | 0x0     | NtAccessCheck
 0x6fa | 0x9d0a0  | 0x9c4a0 | 0x0     | ZwAccessCheck
 0x29b | 0x9d0c0  | 0x9c4c0 | 0x1     | NtWorkerFactoryWorkerReady
 0x8cc | 0x9d0c0  | 0x9c4c0 | 0x1     | ZwWorkerFactoryWorkerReady
 0xc7  | 0x9d0e0  | 0x9c4e0 | 0x2     | NtAcceptConnectPort
 
 ........ // contents clipped for brevity
 
 syscalls found in win32u.dll (C:\Windows\System32\win32u.dll):

 Fun   |  entry   |  file   | syscall | function name
 Ord   |  RVA     |  offset | id      |
 ----- | -------  | ------- |-------  | -----------------------------------
 0x3e6 | 0x1030   | 0x430   | 0x1000  | NtUserGetThreadState
 0x44c | 0x1050   | 0x450   | 0x1001  | NtUserPeekMessage
 0x30d | 0x1070   | 0x470   | 0x1002  | NtUserCallOneParam
 0x3b3 | 0x1090   | 0x490   | 0x1003  | NtUserGetKeyState
 ........ // contents clipped for brevity
```



## syscall_finder:

You need to provide the required syscall ids or names in the `syscall_finder.py` to resolve accordingly.

Example: [within python script]

```python
    # Example usage for syscall name to ID
    syscall_names = ["NtClose", "NtOpenProcess", "NtReadFile", "NtUserGetOemBitmapSize"]  # Example values, change this accordingly
    for syscall_name in syscall_names:
        print_syscall_id(syscall_name_to_id, syscall_name)
    
    
    # Example usage for syscall ID to name
    syscall_ids = [0x32, 0x3A, 0x42]  # Example values, change this accordingly
    for syscall_id in syscall_ids:
        print_syscall_name(syscall_id_to_name, syscall_id)
```

Output:

```cmd
C:\Users\ElNino\Desktop\syscall_tools>syscall_finder.py
OS Info:
[Windows 10] ver. 10.0.19044

Syscall Name: NtClose, Syscall ID (hex): 0xf
Syscall Name: NtOpenProcess, Syscall ID (hex): 0x26
Syscall Name: NtReadFile, Syscall ID (hex): 0x6
Syscall Name: NtUserGetOemBitmapSize, Syscall ID (hex): 0x141e
Syscall ID (hex) : 0x32, Syscall Name: ZwEnumerateKey
Syscall ID (hex) : 0x3a, Syscall Name: ZwWriteVirtualMemory
Syscall ID (hex) : 0x42, Syscall Name: ZwDuplicateToken
```



## How do these tools work?

1. Read the .dll from disk
2. Parse the Export Address Table and get the RVA of the export's code.
3. Convert the RVA to file offset and look for **'syscall stub'** pattern.

```assembly
  4C 8B D1                 |  mov r10, rcx
  B8 -- -- -- --           |  mov eax, <syscall id>
  F6 04 25 -- -- -- -- --  |  test byte ptr ds:[-- -- -- --], --
  75 03                    |  jne ntdll.xxxxxxxx        // jump 3 bytes from the end of this instruction.
  0F 05                    |  syscall
  C3                       |  ret
  CD 2E                    |  int 2E                   // jump here if not equal.
  C3                       |  ret
```

4. Once the pattern is found, the syscall id is extracted. The size of syscall id is 4 bytes.
5. Two dictionaries are built with syscall ids and names as keys for faster 'id to name' and 'name to id' mapping.