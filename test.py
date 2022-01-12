from PyQt4 import QtGui
import os


class createedditConvertorpage(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)


def selectFilecsvtoxml(self):
    directory = QtGui.QFileDialog.getExistingDirectory(self, "Pick a folder")
    print directory
    self.listDirPath.setText(directory)

    for file_name in os.listdir(directory):
        if not file_name.startswith("."):
            print (file_name) + "   this is selectFilcestoxml"
    self.directory = directory
    return directory


class readoutWindow(QtGui.QDialog):
    def openTxt(self):
        directoryFile = createedditConvertorpage()
        dir1 = directoryFile.selectFilecsvtoxml()
        print "this s open text"
        print str(dir1)
        for file_name in dir1:
            if file_name.endswith(".txt"):
                print (file_name) + "   this is txt file"
