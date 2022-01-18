# coding=utf-8
# -*- coding: utf-8 -*-
# (or w/ever other coding you use for unicode literals;-)
import sys
import pefile
from PyQt4 import QtGui, QtCore, Qt
from table import TableView


class Window(QtGui.QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.name = QtGui.QFileDialog.getOpenFileName(

            self, 'Open File', '', 'All Files(*.exe*)')

        self.pe = pefile.PE(self.name, fast_load=True)
        self.textEdit = QtGui.QTextEdit()
        self.toolBar = self.addToolBar("Extraction")
        self.section = QtGui.QTextEdit()
        self.section_header = QtGui.QTextEdit()
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
                                                 , 'Reserved', 'OEM Identifier', 'OEM Information', 'Reserved',
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
                            'Value': ['IMAGE_FILE_MACHINE_I386', '',
                                      self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]]}
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
        self.file_open()
        self.create_list_button()

    def create_list_button(self):
        # program_data = {'Value': str(lambda: self.read_program_value(self.name))}
        # print (program_data)
        program = QtGui.QPushButton("PROGRAM", self)
        program.setStyleSheet("font-size: 25px;")

        image_dos_header = QtGui.QPushButton("IMAGE_DOS_HEADER", self)
        image_dos_header.setStyleSheet("font-size: 25px;")

        optional_header = QtGui.QPushButton("OPTIONAL_HEADER", self)
        optional_header.setStyleSheet("font-size: 25px")

        signature = QtGui.QPushButton("SIGNATURE", self)
        signature.setStyleSheet("font-size: 25px")

        image_file_header = QtGui.QPushButton("IMAGE_FILE_HEADER", self)
        image_file_header.setStyleSheet("font-size: 25px")

        image_section_header = QtGui.QPushButton("IMAGE_SECTION_HEADER", self)
        image_section_header.setStyleSheet("font-size: 25px")

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

        image_section_header.resize(350, 30)
        image_section_header.move(782, 400)
        image_section_header.show()

        section.resize(350, 30)
        section.move(782, 450)
        section.show()

        # handle button
        program.clicked.connect(self.display_table_program)
        image_dos_header.clicked.connect(self.display_table_image_dos_header)
        signature.clicked.connect(self.display_table_signature)
        image_file_header.clicked.connect(self.display_table_file_header)

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

    def file_open(self):
        """Open Exe File"""
        self.pe.full_load()

    def read_program_value(self):
        """Read Binary File"""
        return self.pe.header

    def read_optional_header(self, pe):
        """Read Optional Header"""
        self.optional_header.setReadOnly(True)
        for data_dir in pe.OPTIONAL_HEADER.dump():
            self.setCentralWidget(self.optional_header)
            self.optional_header.append(data_dir)

    def read_ms_dos_stub_program(self, pe):
        pass

    def read_image_nt_header(self, pe):
        pass

    def read_signature(self, pe):
        """Read NT_HEADERS Signature"""
        for field in pe.NT_HEADERS.dump():
            self.setCentralWidget(self.signature)
            self.signature.append(field)

    def read_image_file_header(self, pe):
        """Read NT_HEADERS FILE_HEADER"""
        self.file_header.setReadOnly(True)
        for field in pe.FILE_HEADER.dump():
            self.setCentralWidget(self.file_header)
            self.file_header.append(field)

    def read_image_section_header(self, pe):
        """Read Image Section Header"""
        self.section_header.setReadOnly(True)
        self.setCentralWidget(self.section_header)
        self.section_header.setPlainText(
            ' '.join(map(str, pe.sections)))

    def read_sections(self, pe):
        """Read Section Header"""
        self.section.setReadOnly(True)
        for section in pe.sections:
            self.setCentralWidget(self.section)
            self.section.append(section.Name.decode('utf-8'))
            self.section.append("Virtual Address: " +
                                hex(section.VirtualAddress))
            self.section.append("Virtual Size: " +
                                hex(section.Misc_VirtualSize))
            self.section.append(
                "Raw Size: " + hex(section.SizeOfRawData))

    def close_application(self):
        """Close Application"""
        sys.exit()


def run():
    app = QtGui.QApplication(sys.argv)
    GUI = Window()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
