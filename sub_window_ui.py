from PyQt4 import QtGui
from main_window_ui import Window


class SubWindow(Window):
    def __init__(self):
        Window.__init__(self)
        super(SubWindow, self).__init__()

        self.mdi = QtGui.QMdiArea()
        self.setCentralWidget(self.mdi)

    def create_sub_window(self, width, height):
        sub_window = QtGui.QMdiSubWindow()
        self.edit = QtGui.QTextEdit()
        self.edit.setReadOnly(True)
        sub_window.setWidget(self.edit)
        self.mdi.addSubWindow(sub_window)
        sub_window.setMinimumSize(width, height)
