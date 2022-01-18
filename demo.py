import pefile
import mmap

exe_path = "./trojan-killer_2021.exe"

# Map the executable in memory
fd = open(exe_path, 'rb')
pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
print(pe_data)

# Parse the data contained in the buffer
pe = pefile.PE(data=pe_data)
lst_dos_header = []
for val_dos_header in pe.DOS_HEADER.dump():
    lst_dos_header.append(val_dos_header)
print(pe.DOS_HEADER.__keys__)
