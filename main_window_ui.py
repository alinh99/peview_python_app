# coding=utf-8
# -*- coding: utf-8 -*-
# (or w/ever other coding you use for unicode literals;-)
import sys
import pefile
from PyQt4 import QtGui
from table import TableView
import functools


def read_image_section_header_name(pe):
    """Read Image Section Header"""
    for section in pe.sections:
        return section.name


class Window(QtGui.QMainWindow):
    def __init__(self):
        super(Window, self).__init__()

        self.lst_image_section = []
        self.name = QtGui.QFileDialog.getOpenFileName(

            self, 'Open File', '', 'All Files(*.exe*)')
        # self.index = 0
        self.pe = pefile.PE(self.name, fast_load=True)
        self.image_section_header = {"Data": [],
                                     "pFile": [],
                                     "Description": ['Name', 'Virtual Size', 'RVA', 'Size of Raw Data',
                                                     'Pointer to Raw Data', 'Pointer to Relocations',
                                                     'Pointer to Line Numbers', 'Number of Relocations',
                                                     'Number of Line Numbers', 'Characteristics'],
                                     "Value": []}
        self.textEdit = QtGui.QTextEdit()
        self.toolBar = self.addToolBar("Extraction")
        self.section = QtGui.QTextEdit()

        self.program_value = {'Value': [str(self.read_program_value())]}

        self.image_dos_header = {'Data': [hex(self.pe.DOS_HEADER.dump_dict()['e_magic']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_cblp']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_cp']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_crlc']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_cparhdr']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_minalloc']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_maxalloc']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_ss']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_sp']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_csum']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_ip']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_cs']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_lfarlc']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_ovno']['Value']),
                                          (self.pe.DOS_HEADER.dump_dict()['e_res']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_oemid']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_oeminfo']['Value']),
                                          (self.pe.DOS_HEADER.dump_dict()['e_res2']['Value']),
                                          hex(self.pe.DOS_HEADER.dump_dict()['e_lfanew']['Value'])],

                                 'pFile': [hex(self.pe.DOS_HEADER.dump_dict()['e_magic']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_cblp']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_cp']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_crlc']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_cparhdr']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_minalloc']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_maxalloc']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_ss']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_sp']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_csum']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_ip']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_cs']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_lfarlc']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_ovno']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_res']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_oemid']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_oeminfo']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_res2']['FileOffset']),
                                           hex(self.pe.DOS_HEADER.dump_dict()['e_lfanew']['FileOffset'])],

                                 'Description': ['Signature', 'Bytes on Last Page of File', 'Pages in File',
                                                 'Relocations', 'Size of Header in Paragraphs',
                                                 'Minimum Extra Paragraphs', 'Maximum Extra Paragraphs',
                                                 'Initial (relative) SS', 'Initial SP', 'Checksum', 'Initial IP',
                                                 'Initial (relative) CS', 'Offset to Relocation Table', 'Overlay Number'
                                                                                                        'Reserved',
                                                 'OEM Identifier', 'OEM Information', 'Reserved',
                                                 'Offset to New EXE Header'],

                                 'Value': ['IMAGE_DOS_SIGNATURE MZ']}

        self.signature = {'Data': [hex(self.pe.NT_HEADERS.dump_dict()['Signature']['Value'])],

                          'pFile': [hex(self.pe.NT_HEADERS.dump_dict()['Signature']['FileOffset'])],

                          'Description': ['Signature'],

                          'Value': ['IMAGE_NT_SIGNATURE PE']}

        self.file_header = {'Data': [hex(self.pe.FILE_HEADER.dump_dict()['Machine']['Value']),
                                     hex(self.pe.FILE_HEADER.dump_dict()['NumberOfSections']['Value']),
                                     self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[0][:-1],
                                     hex(self.pe.FILE_HEADER.dump_dict()['PointerToSymbolTable']['Value']),
                                     hex(self.pe.FILE_HEADER.dump_dict()['NumberOfSymbols']['Value']),
                                     hex(self.pe.FILE_HEADER.dump_dict()['SizeOfOptionalHeader']['Value']),
                                     hex(self.pe.FILE_HEADER.dump_dict()['Characteristics']['Value'])],

                            'pFile': [hex(self.pe.FILE_HEADER.dump_dict()['Machine']['FileOffset']),
                                      hex(self.pe.FILE_HEADER.dump_dict()['NumberOfSections']['FileOffset']),
                                      hex(self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['FileOffset']),
                                      hex(self.pe.FILE_HEADER.dump_dict()['PointerToSymbolTable']['FileOffset']),
                                      hex(self.pe.FILE_HEADER.dump_dict()['NumberOfSymbols']['FileOffset']),
                                      hex(self.pe.FILE_HEADER.dump_dict()['SizeOfOptionalHeader']['FileOffset']),
                                      hex(self.pe.FILE_HEADER.dump_dict()['Characteristics']['FileOffset'])],

                            'Description': ['Machine', 'Number of Sections', 'Time Date Stamp',
                                            'Pointer to Symbol Table', 'Number of Symbols', 'Size of Optional Header',
                                            'Characteristics'],

                            'Value': ['', '',
                                      self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]]}

        self.optional_header = {'Data': [hex(self.pe.OPTIONAL_HEADER.dump_dict()['Magic']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorLinkerVersion']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorLinkerVersion']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfCode']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfInitializedData']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfUninitializedData']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['AddressOfEntryPoint']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['BaseOfCode']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['BaseOfData']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['ImageBase']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SectionAlignment']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['FileAlignment']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorOperatingSystemVersion'][
                                                 'Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorOperatingSystemVersion'][
                                                 'Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorImageVersion']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorImageVersion']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorSubsystemVersion']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorSubsystemVersion']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['Reserved1']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfImage']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfHeaders']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['CheckSum']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['Subsystem']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['DllCharacteristics']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfStackReserve']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfStackCommit']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfHeapReserve']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfHeapCommit']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['LoaderFlags']['Value']),
                                         hex(self.pe.OPTIONAL_HEADER.dump_dict()['NumberOfRvaAndSizes']['Value'])],

                                'pFile': [hex(self.pe.OPTIONAL_HEADER.dump_dict()['Magic']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorLinkerVersion']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorLinkerVersion']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfCode']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfInitializedData'][
                                                  'FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfUninitializedData'][
                                                  'FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['AddressOfEntryPoint']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['BaseOfCode']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['BaseOfData']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['ImageBase']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SectionAlignment']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['FileAlignment']['Value']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorOperatingSystemVersion'][
                                                  'FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorOperatingSystemVersion'][
                                                  'FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorImageVersion']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorImageVersion']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MajorSubsystemVersion'][
                                                  'FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['MinorSubsystemVersion'][
                                                  'FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['Reserved1']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfImage']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfHeaders']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['CheckSum']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['Subsystem']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['DllCharacteristics']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfStackReserve']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfStackCommit']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfHeapReserve']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['SizeOfHeapCommit']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['LoaderFlags']['FileOffset']),
                                          hex(self.pe.OPTIONAL_HEADER.dump_dict()['NumberOfRvaAndSizes'][
                                                  'FileOffset'])],

                                'Description': ['Magic', 'Major Linker Version', 'Minor Linker Version', 'Size of Code',
                                                'Size of Initialized Data', 'Size of Uninitialized Data',
                                                'Address of Entry Point', 'Base of Code', 'Base of Data', 'Image Base',
                                                'Section Alignment', 'File Alignment', 'Major Operating System Version',
                                                'Minor Operating System Version', 'Major Image Version',
                                                'Minor Image Version', 'Major Subsystem Version',
                                                'Minor Subsystem Version', 'Win32 Version Value', 'Size of Image',
                                                'Size of Headers', 'Checksum', 'Subsystem', 'Dll Characteristics',
                                                'Size of Stack Reserve', 'Size of Stack Commit', 'Size of Heap Reserve',
                                                'Size of Heap Commit', 'Loader Flags', 'Number of Data Directories'],
                                'Value': ['IMAGE_NT_OPTIONAL_HDR32_MAGIC']}

        # set size of main window
        self.setGeometry(25, 25, 4000, 4000)

        # display main window as maximized
        self.showMaximized()

        # set window title
        self.setWindowTitle("PE Views")

        # add icon of window
        self.setWindowIcon(QtGui.QIcon('./icons/search.png'))

        # Open file in menu bar
        openFile = QtGui.QAction("&Open File", self)
        openFile.setShortcut("Ctrl+O")
        openFile.setStatusTip('Open File')
        openFile.triggered.connect(self.file_open)

        # Exit application
        exit_app = QtGui.QAction("&Exit", self)
        exit_app.setShortcut("Alt+F4")
        exit_app.setStatusTip('Exit')
        exit_app.triggered.connect(self.close_application)
        self.statusBar()

        # Add menuBar
        mainMenu = self.menuBar()

        # Add fileMenu in menuBar
        fileMenu = mainMenu.addMenu('&File')

        # Add action in fileMenu
        fileMenu.addAction(openFile)
        fileMenu.addAction(exit_app)

        self.toolbar()
        # self.image_section_file_offset(key="Name", i)
        self.create_list_button()
        # self.display_table_image_section_header()

    def create_list_button(self):
        # program_data = {'Value': str(lambda: self.read_program_value(self.name))}
        # print (program_data)
        program = QtGui.QPushButton("PROGRAM", self)
        program.setStyleSheet("font-size: 25px;")

        image_dos_header = QtGui.QPushButton(self.pe.DOS_HEADER.name, self)
        image_dos_header.setStyleSheet("font-size: 25px;")

        optional_header = QtGui.QPushButton(self.pe.OPTIONAL_HEADER.name, self)
        optional_header.setStyleSheet("font-size: 25px")

        signature = QtGui.QPushButton(self.pe.NT_HEADERS.dump_dict().keys()[1], self)
        signature.setStyleSheet("font-size: 25px")

        image_file_header = QtGui.QPushButton(self.pe.FILE_HEADER.name, self)
        image_file_header.setStyleSheet("font-size: 25px")

        for section in self.pe.sections:
            self.lst_image_section.append(section.Name)

        image_section_header = QtGui.QPushButton("IMAGE SECTION HEADER", self)
        image_section_header.setStyleSheet("font-size: 25px")
        image_section_header.resize(350, 30)
        image_section_header.move(782, 400)

        menu_image_section_header = QtGui.QMenu()

        for index, i in enumerate(self.lst_image_section):
            item_image_section = menu_image_section_header.addAction("IMAGE SECTION HEADER " + i)
            item_image_section.triggered.connect(
                functools.partial(self.dispaly_image_section_table, index))

        image_section_header.setMenu(menu_image_section_header)
        image_section_header.show()
        section = QtGui.QPushButton("SECTION", self)
        section.setStyleSheet("font-size: 25px")

        program.resize(350, 30)
        program.move(782, 150)
        program.show()

        image_dos_header.resize(350, 30)
        image_dos_header.move(782, 200)
        image_dos_header.show()

        optional_header.resize(350, 30)
        optional_header.move(782, 250)
        optional_header.show()

        signature.resize(350, 30)
        signature.move(782, 300)
        signature.show()

        image_file_header.resize(350, 30)
        image_file_header.move(782, 350)
        image_file_header.show()

        section.resize(350, 30)
        section.move(782, 450)
        section.show()

        # handle button
        program.clicked.connect(self.display_table_program)
        image_dos_header.clicked.connect(self.display_table_image_dos_header)
        signature.clicked.connect(self.display_table_signature)
        image_file_header.clicked.connect(self.display_table_file_header)
        optional_header.clicked.connect(self.display_table_optional_header)

    def toolbar(self):
        """Display toolbar"""
        openFileAction = QtGui.QAction(QtGui.QIcon(
            './icons/exe_file.png'), 'Read Exe File', self)
        openFileAction.triggered.connect(self.file_open)
        quitAction = QtGui.QAction(
            QtGui.QIcon('./icons/exit_button.png'), 'Quit', self)
        quitAction.triggered.connect(self.close_application)
        self.toolBar.addAction(openFileAction)
        self.toolBar.addAction(quitAction)

        self.show()

    def display_table_program(self):
        table_program = TableView(self.program_value, 3, 1)
        # table.setWindowFlags(table.windowFlags() | Qt.Window)
        table_program.show()
        self.table = table_program
        # self.read_program_value(self.name)

    def display_table_image_dos_header(self):
        table_image_dos_header = TableView(self.image_dos_header, 19, 4)
        table_image_dos_header.show()
        self.table = table_image_dos_header

    def display_table_signature(self):
        table_signature = TableView(self.signature, 1, 4)
        table_signature.show()
        self.table = table_signature

    def display_table_file_header(self):
        table_file_header = TableView(self.file_header, 7, 4)
        table_file_header.show()
        self.table = table_file_header

    def display_table_optional_header(self):
        table_optional_header = TableView(self.optional_header, 30, 4)
        table_optional_header.show()
        self.table = table_optional_header

    def dispaly_image_section_table(self, i):
        data = {"Data": ["",
                         hex(self.pe.sections[i].dump_dict()["Misc"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["VirtualAddress"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["SizeOfRawData"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["PointerToRawData"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["PointerToRelocations"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["PointerToLinenumbers"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["NumberOfRelocations"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["NumberOfLinenumbers"]["Value"]),
                         hex(self.pe.sections[i].dump_dict()["Characteristics"]["Value"])],

                "pFile": [hex(self.pe.sections[i].dump_dict()["Name"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["Misc"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["VirtualAddress"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["SizeOfRawData"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["PointerToRawData"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["PointerToRelocations"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["PointerToLinenumbers"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["NumberOfRelocations"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["NumberOfLinenumbers"]["FileOffset"]),
                         hex(self.pe.sections[i].dump_dict()["Characteristics"]["FileOffset"])],

                "Value": [self.pe.sections[i].dump_dict()["Name"]["Value"]],
                "Description": ['Name', 'Virtual Size', 'RVA', 'Size of Raw Data',
                                'Pointer to Raw Data', 'Pointer to Relocations',
                                'Pointer to Line Numbers', 'Number of Relocations',
                                'Number of Line Numbers', 'Characteristics']
                }
        # return value_file_offset[i]
        table_image_section_header = TableView(data, 10, 4)
        table_image_section_header.show()
        self.table = table_image_section_header

    def display_table_image_section_header(self):
        # for i in range(3):
        table_image_section_header = TableView(self.image_section_header, 10, 4)
        table_image_section_header.show()
        self.table = table_image_section_header

    def file_open(self):
        """Open Exe File"""
        self.name = QtGui.QFileDialog.getOpenFileName(

            self, 'Open File', '', 'All Files(*.exe*)')

        self.pe = pefile.PE(self.name, fast_load=True)
        self.pe.full_load()

    def read_program_value(self):
        """Read Binary File"""
        return self.pe.header

    def close_application(self):
        """Close Application"""
        sys.exit()


def run():
    app = QtGui.QApplication(sys.argv)
    GUI = Window()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
