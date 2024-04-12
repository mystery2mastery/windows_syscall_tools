'''
    Author: G. Narasimha Reddy
'''

import pefile
import struct
import platform

'''
// syscall stub in x64 Windows OS:

  4C 8B D1                | mov r10, rcx
  B8 -- -- -- --          | mov eax, <syscall id>
  F6 04 25 -- -- -- -- -- | test byte ptr ds:[-- -- -- --], --
  75 03                   | jne ntdll.xxxxxxxx                      // jump 3 bytes from the end of this instruction.
  0F 05                   | syscall
  C3                      | ret
  CD 2E                   | int 2E                                 // jump here if not equal.
  C3                      | ret
  
'''

def is_syscall_stub(code):
    # Check if the code matches the syscall stub pattern
    return (
        len(code) >= 24 and
        code[0:4] == b'\x4C\x8B\xD1\xB8' and
        code[8:11] == b'\xF6\x04\x25' and
        code[16:24] == b'\x75\x03\x0F\x05\xC3\xCD\x2E\xC3'
    )

def extract_syscall_id(code):
    # Extract syscall ID from the code
    syscall_id = struct.unpack('I', code[4:8])[0]  # Assuming syscall id is a 4-byte little-endian integer
    return syscall_id

def parse_exports(dll_path):
    try:
        pe = pefile.PE(dll_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            export_table = pe.DIRECTORY_ENTRY_EXPORT.symbols
            
            # Create a list to store export information
            export_info = []
            
            for exp in export_table:
                if exp.address:
                    export_offset = pe.get_offset_from_rva(exp.address)
                    code = pe.get_data(exp.address, 24)
                    if is_syscall_stub(code):
                        syscall_id = extract_syscall_id(code)
                        export_info.append((exp.ordinal, exp.address, export_offset, syscall_id, exp.name.decode() if exp.name else 'No Name'))
            
            # Sort the export information based on syscall ID
            export_info.sort(key=lambda x: x[3])   # 0 => Fun Ord; 3 => syscall id
            
            # Print the information
            print(" Fun   |  entry   |  file   | syscall | function name")
            print(" Ord   |  RVA     |  offset | id      | ")
            print(" ----- | -------  | ------- |-------  | -----------------------------------")
            for info in export_info:
                print(f" {hex(info[0]):5} | {hex(info[1]):8} | {hex(info[2]):7} | {hex(info[3]):7} | {info[4]}")
                    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Print OS info.
    print("OS Info:")
    print(f"[{platform.system()} {platform.release()}] ver. {platform.version()}")
    
    # Print syscalls in 'ntdll.dll'
    print("\nsyscalls found in ntdll.dll (C:\\Windows\\System32\\ntdll.dll):\n")
    dll_path = "C:\\Windows\\System32\\ntdll.dll"  # Change this path accordingly    
    parse_exports(dll_path)
    
    print("\nsyscalls found in win32u.dll (C:\\Windows\\System32\\win32u.dll):\n")
    dll_path = "C:\\Windows\\System32\\win32u.dll"  # Change this path accordingly    
    parse_exports(dll_path)    
