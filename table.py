from PyQt4 import QtGui, QtCore


class TableView(QtGui.QTableWidget):
    def __init__(self, data, *args):
        QtGui.QTableWidget.__init__(self, *args)
        self.data = data
        self.setData()
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.verticalHeader().sectionResized.connect(self.fitToTable)
        self.horizontalHeader().sectionResized.connect(self.fitToTable)
        self.resizeColumnsToContents()
        self.resizeRowsToContents()
        self.fitToTable()

    def setData(self):
        horHeaders = []
        # print self.data
        for n, key in enumerate(sorted(self.data.keys())):
            horHeaders.append(key)
            for m, item in enumerate(self.data[key]):
                newitem = QtGui.QTableWidgetItem(item)
                self.setItem(m, n, newitem)
        self.setHorizontalHeaderLabels(horHeaders)

    @QtCore.pyqtSlot()
    def fitToTable(self):
        x = self.verticalHeader().size().width()
        for i in range(self.columnCount()):
            x += self.columnWidth(i)

        y = self.horizontalHeader().size().height()
        for i in range(self.rowCount()):
            y += self.rowHeight(i)

        self.setFixedSize(x, y)