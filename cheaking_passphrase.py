# Form implementation generated from reading ui file 'cheaking_passphrase.ui'
#
# Created by: PyQt6 UI code generator 6.3.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class UiCheakingPassphrase(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(400, 200)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(30, 140, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Cancel|QtWidgets.QDialogButtonBox.StandardButton.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(70, 20, 271, 21))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.label.setFont(font)
        self.label.setObjectName("label")

        self.passphrase = QtWidgets.QLineEdit(Dialog)
        self.passphrase.setGeometry(QtCore.QRect(70, 60, 261, 27))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.passphrase.setFont(font)
        self.passphrase.setObjectName("passphrase")
        self.passphrase.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.checkBox = QtWidgets.QCheckBox(Dialog)
        self.checkBox.setGeometry(QtCore.QRect(220, 100, 113, 20))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.checkBox.setFont(font)
        self.checkBox.setObjectName("checkBox")

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept) # type: ignore
        self.buttonBox.rejected.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)
        self.buttonBox.clicked.connect(self.save_passphrase)
        self.checkBox.clicked.connect(self.change_passphrase_visibility)

    def save_passphrase(self):
        return self.passphrase.text()

    def change_passphrase_visibility(self):
        if self.checkBox.isChecked():
            self.passphrase.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.passphrase.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Cheaking passphrase"))
        self.checkBox.setText(_translate("Dialog", "show passphrase"))
        self.label.setText(_translate("Dialog", "Enter passphrase to import certificate:"))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = UiCheakingPassphrase()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec())