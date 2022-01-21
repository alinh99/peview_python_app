from PyQt4 import QtGui


class TableView(QtGui.QTableWidget):
    def __init__(self, data, *args):
        QtGui.QTableWidget.__init__(self, *args)
        self.data = data
        self.setData()
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setResizeMode(QtGui.QHeaderView.ResizeToContents)
        header.setResizeMode(0, QtGui.QHeaderView.Stretch)
        header.setResizeMode(1, QtGui.QHeaderView.Stretch)
        header.setResizeMode(2, QtGui.QHeaderView.Stretch)
        header.setResizeMode(3, QtGui.QHeaderView.Stretch)
        self.maximumHeight()
        self.maximumWidth()
        self.showMaximized()


    def setData(self):
        horHeaders = []
        # print self.data
        for n, key in enumerate(sorted(self.data.keys())):
            horHeaders.append(key)
            for m, item in enumerate(self.data[key]):
                newitem = QtGui.QTableWidgetItem(item)
                self.setItem(m, n, newitem)
        self.setHorizontalHeaderLabels(horHeaders)

