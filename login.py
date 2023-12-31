# Form implementation generated from reading ui file 'login_3.ui'
#
# Created by: PyQt6 UI code generator 6.3.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Login_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(400, 300)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(30, 240, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Cancel|QtWidgets.QDialogButtonBox.StandardButton.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(180, 10, 60, 21))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(9, 70, 71, 20))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(Dialog)
        self.label_3.setGeometry(QtCore.QRect(10, 100, 71, 20))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(Dialog)
        self.label_4.setGeometry(QtCore.QRect(10, 210, 151, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")

        self.user_name = QtWidgets.QLineEdit(Dialog)
        self.user_name.setGeometry(QtCore.QRect(100, 70, 241, 21))
        self.user_name.setObjectName("user_name")

        self.password = QtWidgets.QLineEdit(Dialog)
        self.password.setGeometry(QtCore.QRect(100, 100, 241, 21))
        self.password.setObjectName("password")
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.checkBox = QtWidgets.QCheckBox(Dialog)
        self.checkBox.setGeometry(QtCore.QRect(235, 130, 140, 20))
        font = QtGui.QFont()
        font.setPointSize(11)

        self.checkBox.setFont(font)
        self.checkBox.setObjectName("checkBox")

        self.registr = QtWidgets.QPushButton(Dialog)
        self.registr.setGeometry(QtCore.QRect(10, 240, 113, 32))
        self.registr.setObjectName("registration")

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept) # type: ignore
        self.buttonBox.rejected.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)
        self.checkBox.clicked.connect(self.change_password_visibility)
        
    
    def saveText(self):
        return self.user_name.text(), self.password.text()



    def change_password_visibility(self):
        if self.checkBox.isChecked():
            self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)


    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Login"))
        self.label.setText(_translate("Dialog", "Login"))
        self.label_2.setText(_translate("Dialog", "User name:"))
        self.label_3.setText(_translate("Dialog", "Password:"))
        self.checkBox.setText(_translate("Dialog", "show password"))
        self.registr.setText(_translate("Dialog", "Registration"))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Login_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec())
