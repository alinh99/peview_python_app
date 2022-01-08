# coding=utf-8
import sys
import pefile
from PyQt4 import QtGui
import codecs


class Window(QtGui.QMainWindow):
    def __init__(self):
        super(Window, self).__init__()

        # Add button_sub_window
        self.mdi = QtGui.QMdiArea()
        self.setCentralWidget(self.mdi)

        button_sub_window = QtGui.QMdiSubWindow()
        self.edit_button = QtGui.QTextEdit()
        self.edit_button.setReadOnly(True)
        button_sub_window.setWidget(self.edit_button)

        self.mdi.addSubWindow(button_sub_window)
        button_sub_window.setMinimumSize(600, 1000)
        button_sub_window.show()

        # Add value_sub_window
        value_sub_window = QtGui.QMdiSubWindow()
        self.edit_value = QtGui.QTextEdit()
        self.edit_value.setReadOnly(True)
        value_sub_window.setWidget(self.edit_value)

        self.mdi.addSubWindow(value_sub_window)
        value_sub_window.setMinimumSize(1325, 1325)
        value_sub_window.show()

        self.setGeometry(25, 25, 4000, 4000)
        self.showMaximized()
        self.setWindowTitle("PE Views")
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

        self.home()

    def home(self):
        openFileAction = QtGui.QAction(QtGui.QIcon(
            './icons/exe_file.png'), 'Read Exe File', self)
        openFileAction.triggered.connect(self.file_open)
        quitAction = QtGui.QAction(
            QtGui.QIcon('./icons/exit_button.png'), 'Quit', self)
        quitAction.triggered.connect(self.close_application)
        self.toolBar = self.addToolBar("Extraction")
        self.toolBar.addAction(openFileAction)
        self.toolBar.addAction(quitAction)

        self.show()

    def file_open(self):
        """Open Exe File"""
        name = QtGui.QFileDialog.getOpenFileName(

            self, 'Open File', '', 'All Files(*.exe*)')
        pe = pefile.PE(name, fast_load=True)
        pe.full_load()
        self.editor()
        self.textEdit.setReadOnly(True)
        self.read_image_dos_header(pe)
        self.read_optional_header(pe)
        self.read_image_section_header(pe)
        self.read_sections(pe)
        self.read_signature(pe)
        self.read_image_file_header(pe)

    def read_binary(self, name):
        """Read Binary File"""
        s = codecs.open(name, 'rb', 'mbcs').read()
        self.editor()
        self.textEdit.setReadOnly(True)
        self.textEdit.setPlainText(s)

    def read_image_dos_header(self, pe):
        """Read Image Dos Header"""
        self.dos_header = QtGui.QTextEdit()
        self.dos_header.setReadOnly(True)
        for field in pe.DOS_HEADER.dump():
            self.setCentralWidget(self.dos_header)
            self.dos_header.append(field)

    def read_optional_header(self, pe):
        """Read Optional Header"""
        self.optional_header = QtGui.QTextEdit()
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
        self.signature = QtGui.QTextEdit()
        for field in pe.NT_HEADERS.dump():
            self.setCentralWidget(self.signature)
            self.signature.append(field)

    def read_image_file_header(self, pe):
        """Read NT_HEADERS FILE_HEADER"""
        self.file_header = QtGui.QTextEdit()
        self.file_header.setReadOnly(True)
        for field in pe.FILE_HEADER.dump():
            self.setCentralWidget(self.file_header)
            self.file_header.append(field)

    def read_image_section_header(self, pe):
        """Read Image Section Header"""
        self.section_header = QtGui.QTextEdit()
        self.section_header.setReadOnly(True)
        self.setCentralWidget(self.section_header)
        self.section_header.setPlainText(
            ' '.join(map(str, pe.sections)))

    def read_sections(self, pe):
        """Read Section Header"""
        self.section = QtGui.QTextEdit()
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
        sys.exit(0)

    def editor(self):
        """Edit data"""
        self.textEdit = QtGui.QTextEdit()
        self.textEdit.setReadOnly(True)
        self.setCentralWidget(self.textEdit)


def run():
    app = QtGui.QApplication(sys.argv)
    GUI = Window()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
