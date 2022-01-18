import pefile
import mmap

exe_path = "./trojan-killer_2021.exe"

# Map the executable in memory
fd = open(exe_path, 'rb')
pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
print(pe_data)

pe = pefile.PE(exe_path)

print pe.OPTIONAL_HEADER
print hex(pe.OPTIONAL_HEADER.dump_dict()['Magic']['FileOffset'])
print hex(pe.OPTIONAL_HEADER.dump_dict()['Magic']['Value'])
abcd = {'Description': ['Magic', 'Major Linker Version', 'Minor Linker Version', 'Size of Code',
                        'Size of Initialized Data', 'Size of Uninitialized Data',
                        'Address of Entry Point', 'Base of Code', 'Base of Data', 'Image Base',
                        'Section Alignment', 'File Alignment', 'Major Operating System Version',
                        'Minor Operating System Version',
                        'Major Image Version', 'Minor Image Version', 'Major Subsystem Version',
                        'Minor Subsystem Version', 'Win32 Version Value', 'Size of Image',
                        'Size of Headers', 'Checksum', 'Subsystem', 'Dll Characteristics',
                        'Size of Stack Reserve', 'Size of Stack Commit', 'Size of Heap Reserve',
                        'Size of Heap Commit', 'Loader Flags', 'Number of Data Directories']}
print len(abcd['Description'])
print(pe.header)
