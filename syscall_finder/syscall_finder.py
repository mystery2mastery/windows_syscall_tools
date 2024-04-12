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

def parse_exports(dll_paths):
    syscall_name_to_id = {}  # Dictionary to store syscall names and IDs
    syscall_id_to_name = {}  # Dictionary to store syscall IDs and names
    
    for dll_path in dll_paths:
        try:
            pe = pefile.PE(dll_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                export_table = pe.DIRECTORY_ENTRY_EXPORT.symbols

                for exp in export_table:
                    if exp.address:
                        export_offset = pe.get_offset_from_rva(exp.address)
                        code = pe.get_data(exp.address, 24)
                        if is_syscall_stub(code):
                            syscall_id = extract_syscall_id(code)
                            syscall_name = exp.name.decode() if exp.name else 'No Name'
                            syscall_name_to_id[syscall_name] = syscall_id
                            syscall_id_to_name[syscall_id] = syscall_name

        except Exception as e:
            print(f"Error: {e}")
    
    return syscall_name_to_id, syscall_id_to_name

def print_syscall_id(syscall_dict, syscall_name):
    if syscall_name in syscall_dict:
        print(f"Syscall Name: {syscall_name}, Syscall ID (hex): {hex(syscall_dict[syscall_name])}")
    else:
        print("Syscall Name not found in the dictionary.")

def print_syscall_name(syscall_dict, syscall_id):
    if syscall_id in syscall_dict:
        print(f"Syscall ID (hex) : {hex(syscall_id)}, Syscall Name: {syscall_dict[syscall_id]}")
    else:
        print("Syscall ID not found in the dictionary.")


if __name__ == "__main__":
    dll_paths = ["C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\win32u.dll"]  # Change this path accordingly
    syscall_name_to_id, syscall_id_to_name = parse_exports(dll_paths)
    
    # Print OS info.
    print("OS Info:")
    print(f"[{platform.system()} {platform.release()}] ver. {platform.version()}\n")
    
    # Example usage for syscall name to ID
    syscall_names = ["NtClose", "NtOpenProcess", "NtReadFile", "NtUserGetOemBitmapSize"]  # Example values, change this accordingly
    for syscall_name in syscall_names:
        print_syscall_id(syscall_name_to_id, syscall_name)
    
    
    # Example usage for syscall ID to name
    syscall_ids = [0x32, 0x3A, 0x42]  # Example values, change this accordingly
    for syscall_id in syscall_ids:
        print_syscall_name(syscall_id_to_name, syscall_id)
