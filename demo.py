import pefile
import mmap

exe_path = "./trojan-killer_2021.exe"

# Map the executable in memory
fd = open(exe_path, 'rb')
pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
print(pe_data)

# Parse the data contained in the buffer
# pe = pefile.PE(data=pe_data)
# lst_dos_header = []
# for val_dos_header in pe.DOS_HEADER.dump():
#     lst_dos_header.append(val_dos_header)
# print(pe.dword_align(None, pe.OPTIONAL_HEADER))

pe = pefile.PE(exe_path)
# print "PE Signature: " + hex(pe.VS_FIXEDFILEINFO.Signature)
print "Image Base: " + hex(pe.OPTIONAL_HEADER.ImageBase)
print "Address of EntryPoint: " + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print "RVA Number and Size: " + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
print "Number of Sections within PE: " + hex(pe.FILE_HEADER.NumberOfSections)
print pe.DOS_HEADER
print hex(pe.DOS_HEADER.dump_dict()['e_magic']['Offset'])
# print hex(pe.DOS_HEADER.dump_dict()['CheckSum']['FileOffset'])
# print(hex(pe.DOS_HEADER.dump_dict()['e_res']['Value']))
# for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
#     print entry.name + "\n|\n|---- Size : " + str(entry.Size) + "\n|\n|---- VirutalAddress : " + hex(entry.VirtualAddress) + '\n'
# lst = []
# for section in pe.sections:
#     lst.append(section)
# print(lst[0])
