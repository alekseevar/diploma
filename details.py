# Form implementation generated from reading ui file 'delails.ui'
#
# Created by: PyQt6 UI code generator 6.3.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_Details(object):
    def setupUi(self, Details):
        Details.setObjectName("Details")
        Details.resize(400, 300)
        self.details = QtWidgets.QLabel(Details)
        self.details.setGeometry(QtCore.QRect(170, 10, 60, 16))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.details.setFont(font)
        self.details.setObjectName("details")
        self.close = QtWidgets.QDialogButtonBox(Details)
        self.close.setGeometry(QtCore.QRect(30, 250, 341, 32))
        self.close.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.close.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Ok)
        self.close.setObjectName("buttonBox")
        #self.close = QtWidgets.QPushButton(Details)
        #self.close.setGeometry(QtCore.QRect(270, 250, 113, 32))
        #self.close.setObjectName("close")
        self.email_label = QtWidgets.QLabel(Details)
        self.email_label.setGeometry(QtCore.QRect(10, 40, 111, 16))
        self.email_label.setObjectName("email_label")
        self.email = QtWidgets.QLabel(Details)
        self.email.setGeometry(QtCore.QRect(150, 40, 600, 16))
        self.email.setText("")
        self.email.setObjectName("email")
        self.name_of = QtWidgets.QLabel(Details)
        self.name_of.setGeometry(QtCore.QRect(150, 60, 600, 16))
        self.name_of.setText("")
        self.name_of.setObjectName("name_of")
        self.user_id_label = QtWidgets.QLabel(Details)
        self.user_id_label.setGeometry(QtCore.QRect(10, 60, 101, 16))
        self.user_id_label.setObjectName("user_id_label")
        self.user_id_of = QtWidgets.QLabel(Details)
        self.user_id_of.setGeometry(QtCore.QRect(150, 80, 600, 16))
        self.user_id_of.setText("")
        self.user_id_of.setObjectName("user_id_of")
        self.user_id_of_label = QtWidgets.QLabel(Details)
        self.user_id_of_label.setGeometry(QtCore.QRect(10, 80, 111, 16))
        self.user_id_of_label.setObjectName("user_id_of_label")
        self.Cert_details_label = QtWidgets.QLabel(Details)
        self.Cert_details_label.setGeometry(QtCore.QRect(130, 115, 151, 20))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.Cert_details_label.setFont(font)
        self.Cert_details_label.setObjectName("Cert_details_label")
        self.valid_from = QtWidgets.QLabel(Details)
        self.valid_from.setGeometry(QtCore.QRect(150, 150, 600, 16))
        self.valid_from.setText("")
        self.valid_from.setObjectName("valid_from")
        self.expires_in = QtWidgets.QLabel(Details)
        self.expires_in.setGeometry(QtCore.QRect(150, 170, 600, 16))
        self.expires_in.setText("")
        self.expires_in.setObjectName("expires_in")
        self.user_id_label_2 = QtWidgets.QLabel(Details)
        self.user_id_label_2.setGeometry(QtCore.QRect(10, 170, 101, 16))
        self.user_id_label_2.setObjectName("user_id_label_2")
        self.curve_name_label = QtWidgets.QLabel(Details)
        self.curve_name_label.setGeometry(QtCore.QRect(10, 190, 111, 16))
        self.curve_name_label.setObjectName("curve_name_label")
        self.curve_name = QtWidgets.QLabel(Details)
        self.curve_name.setGeometry(QtCore.QRect(150, 190, 600, 16))
        self.curve_name.setText("")
        self.curve_name.setObjectName("curve_name")
        self.valid_from_label = QtWidgets.QLabel(Details)
        self.valid_from_label.setGeometry(QtCore.QRect(10, 150, 111, 16))
        self.valid_from_label.setObjectName("valid_from_label")
        self.keyid = QtWidgets.QLabel(Details)
        self.keyid.setGeometry(QtCore.QRect(150, 210, 600, 16))
        self.keyid.setText("")
        self.keyid.setObjectName("keyid")
        self.key_id_label = QtWidgets.QLabel(Details)
        self.key_id_label.setGeometry(QtCore.QRect(10, 210, 111, 16))
        self.key_id_label.setObjectName("key_id_label")

        self.imported = QtWidgets.QLabel(Details)
        self.imported.setGeometry(QtCore.QRect(150, 230, 600, 16))
        self.imported.setText("")
        self.imported.setObjectName("Is Imported?")
        self.imported_label = QtWidgets.QLabel(Details)
        self.imported_label.setGeometry(QtCore.QRect(10, 230, 111, 16))
        self.imported_label.setObjectName("imported")

        #self.change_passphrase = QtWidgets.QPushButton(Details)
        #self.change_passphrase.setGeometry(QtCore.QRect(10, 100, 161, 32))
        #self.change_passphrase.setObjectName("change_passphrase")
        self.export_2 = QtWidgets.QPushButton(Details)
        self.export_2.setGeometry(QtCore.QRect(10, 250, 113, 32))
        self.export_2.setObjectName("export_2")

        
        self.close.accepted.connect(Details.accept)
        self.retranslateUi(Details)
        QtCore.QMetaObject.connectSlotsByName(Details)




    def fill_label(self, email, name, user_id, valid_from, expires_in, curve_name, keyid, imported):
        self.email.setText(str(email))
        self.name_of.setText(str(name))
        self.user_id_of.setText(str(user_id))
        self.valid_from.setText(str(valid_from))
        self.expires_in.setText(str(expires_in))
        self.curve_name.setText(str(curve_name))
        self.keyid.setText(str(keyid))
        self.imported.setText(str(imported))


    def retranslateUi(self, Details):
        _translate = QtCore.QCoreApplication.translate
        Details.setWindowTitle(_translate("Details", "Details"))
        self.details.setText(_translate("Details", "Details"))
        #self.close.setText(_translate("Details", "Close"))
        self.email_label.setText(_translate("Details", "Email of creator"))
        self.user_id_label.setText(_translate("Details", "Name of creator"))
        self.user_id_of_label.setText(_translate("Details", "User id of creator"))
        self.Cert_details_label.setText(_translate("Details", "Certificate Details"))
        self.user_id_label_2.setText(_translate("Details", "Expires in "))
        self.curve_name_label.setText(_translate("Details", "Curve name"))
        self.valid_from_label.setText(_translate("Details", "Valid from"))
        self.key_id_label.setText(_translate("Details", "Key id"))
        self.imported_label.setText(_translate("Details", "Is Imported Cert?"))
        #self.change_passphrase.setText(_translate("Details", "Change passphrase"))
        self.export_2.setText(_translate("Details", "Export"))



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Details()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec())