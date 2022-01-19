import pefile
import mmap
from ast import literal_eval

exe_path = "./trojan-killer_2021.exe"

# Map the executable in memory
fd = open(exe_path, 'rb')
pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)

pe = pefile.PE(exe_path)

# print pe.NT_HEADERS.dump_dict().keys()[1]
# print pe.FILE_HEADER.name
# print hex(pe.sections[0].dump_dict()['Name']['Value'])
# print (pe.sections[0].dump_dict().keys())
# for section in pe.sections:
#     if section.Name:
#         print section.Name
#     else:
#         print("Error")

# for section in pe.sections:
#     print section.dump_dict().keys()

# print pe.sections[0].dump_dict().keys()

for section in pe.sections:
    print hex(section.dump_dict()['']['FileOffset'])