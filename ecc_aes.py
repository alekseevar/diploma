# Form implementation generated from reading ui file 'ecc_aes.ui'
#
# Created by: PyQt6 UI code generator 6.3.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.
from PyQt6 import QtCore, QtGui, QtWidgets
import shortuuid
import hashlib
from datetime import date
import datetime
import os

from create_passphrase import UiCreatePassphrase
from cheaking_passphrase import UiCheakingPassphrase
from share_email import ShareEmail
#from passphrase import UiCreatePassphrase
from change_password import UiChangePassword
from details import Ui_Details
from login import Login_Dialog
from create_cert import Create_CERT
import ecdhe
import aes
import config as cfg
import registration as rg
import ecdsa as sgn
from send_email import share_certificate_via_email

from csv_handler import CsvHandler


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        
        self.MainWindow = MainWindow
        self.MainWindow.setObjectName("MainWindow")
        self.MainWindow.resize(820, 600)

        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 80, 800, 441))
        self.tabWidget.setObjectName("tabWidget")

        self.certificates = QtWidgets.QWidget()
        self.certificates.setObjectName("certificates")
             

        self.cert_table = QtWidgets.QTableWidget(self.certificates)
        self.cert_table.setGeometry(QtCore.QRect(0, 50, 781, 381))
        self.cert_table.setAcceptDrops(False)
        self.cert_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.cert_table.setDragEnabled(False)
        self.cert_table.setDragDropOverwriteMode(False)
        self.cert_table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.cert_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.cert_table.setRowCount(0)
        self.cert_table.setObjectName("cert_table")
        self.cert_table.setColumnCount(5)
        
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.cert_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.cert_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.cert_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.cert_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.cert_table.setHorizontalHeaderItem(4, item)
        self.cert_table.horizontalHeader().setCascadingSectionResizes(False)
        self.cert_table.horizontalHeader().setDefaultSectionSize(152)
        self.cert_table.horizontalHeader().setMinimumSectionSize(20)
        self.cert_table.verticalHeader().setMinimumSectionSize(21)
        

        self.tabWidget.addTab(self.certificates, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")

        self.textEdit = QtWidgets.QTextEdit(self.tab_2)
        self.textEdit.setGeometry(QtCore.QRect(13, 68, 751, 341))
        self.textEdit.setObjectName("textEdit")

        self.Decryptnotepad = QtWidgets.QPushButton(self.tab_2)
        self.Decryptnotepad.setGeometry(QtCore.QRect(150, 10, 131, 51))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.Decryptnotepad.setFont(font)
        self.Decryptnotepad.setObjectName("Decryptnotepad")

        self.encryptnotepad = QtWidgets.QPushButton(self.tab_2)
        self.encryptnotepad.setGeometry(QtCore.QRect(20, 10, 121, 51))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.encryptnotepad.setFont(font)
        self.encryptnotepad.setObjectName("encryptnotepad")

        self.tabWidget.addTab(self.tab_2, "")

        self.Create_keys = QtWidgets.QPushButton(self.centralwidget)
        self.Create_keys.setGeometry(QtCore.QRect(10, 0, 101, 71))
        self.Create_keys.setObjectName("Create_keys")

        self.Encrypt = QtWidgets.QPushButton(self.centralwidget)
        self.Encrypt.setGeometry(QtCore.QRect(110, 0, 101, 71))
        self.Encrypt.setObjectName("Encrypt")
        self.Encrypt.setEnabled(False)

        self.Decrypt = QtWidgets.QPushButton(self.centralwidget)
        self.Decrypt.setGeometry(QtCore.QRect(210, 0, 101, 71))
        self.Decrypt.setObjectName("Decrypt")

        self.Sign = QtWidgets.QPushButton(self.centralwidget)
        self.Sign.setGeometry(QtCore.QRect(310, 0, 101, 71))
        self.Sign.setObjectName("Sign")
        self.Sign.setEnabled(False)

        self.Verify = QtWidgets.QPushButton(self.centralwidget)
        self.Verify.setGeometry(QtCore.QRect(410, 0, 101, 71))
        self.Verify.setObjectName("Verify")

        self.Import = QtWidgets.QPushButton(self.centralwidget)
        self.Import.setGeometry(QtCore.QRect(510, 0, 101, 71))
        self.Import.setObjectName("Import")

        self.Export = QtWidgets.QPushButton(self.centralwidget)
        self.Export.setGeometry(QtCore.QRect(610, 0, 101, 71))
        self.Export.setObjectName("Export")
        self.Export.setEnabled(False)

        self.share_email = QtWidgets.QPushButton(self.centralwidget)
        self.share_email.setGeometry(QtCore.QRect(710, 0, 101, 71))
        self.share_email.setObjectName("Share cert via email")
        self.share_email.setEnabled(False)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setObjectName("menubar")
        MainWindow.menuBar().setNativeMenuBar(False)

        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")

        MainWindow.setStatusBar(self.statusbar)

        self.public_key = [None, None]
        self.private_key = None
        
        self.add_function()
        

        self.login()
        self.csv_handler = CsvHandler(self.path_to_user_file, ["user_id", "name", "email", "key_id", "curve_name", "mod", "isimported", "created_at", "private_key","public_key_x", "public_key_y"], sep=",", cryptor=aes.AESCipher(self.password_user, self.email_user, "CBC"))

        self.createActions(MainWindow)
        self.createMenu(MainWindow)  

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


    def add_function(self):
        self.Create_keys.clicked.connect(self.creating_ecc)
        self.encryptnotepad.clicked.connect(self.encrypt_note_aes)
        self.Decryptnotepad.clicked.connect(self.decrypt_note_aes)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_export)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_encrypt)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_share_email)
        self.cert_table.itemSelectionChanged.connect(self.change_user_choice)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_sign)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_menu_export)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_menu_encrypt)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_menu_sign)
        self.cert_table.itemSelectionChanged.connect(self.change_enable_menu_detail)
    
        self.Import.clicked.connect(self.import_cert)
        self.Export.clicked.connect(self.export_cert)
        self.Encrypt.clicked.connect(self.encrypt_file)
        self.Decrypt.clicked.connect(self.decrypt_file)
        self.Verify.clicked.connect(self.verify_sign)
        self.Sign.clicked.connect(self.sign)
        self.cert_table.itemDoubleClicked.connect(self.details)

        self.share_email.clicked.connect(self.share_by_email)

    
    def createActions(self, main_window):
        self.menu_generate_key_pair = QtGui.QAction("&Create certificate", main_window)
        self.menu_generate_key_pair.setShortcut("Ctrl+N")
        self.menu_generate_key_pair.triggered.connect(self.creating_ecc)

        self.menu_import = QtGui.QAction("Import", main_window)
        self.menu_import.setShortcut("Ctrl+S")
        self.menu_import.triggered.connect(self.import_cert)

        self.menu_export = QtGui.QAction("Export", main_window)
        self.menu_export.setEnabled(False)
        self.menu_export.triggered.connect(self.export_cert)

        self.menu_decrypt = QtGui.QAction("Decypt", main_window)
        self.menu_decrypt.triggered.connect(self.decrypt_file)

        self.menu_verify = QtGui.QAction("Verify", main_window)
        self.menu_verify.triggered.connect(self.verify_sign)
        
        self.menu_encrypt = QtGui.QAction("Encrypt", main_window)
        self.menu_encrypt.setEnabled(False)
        self.menu_encrypt.triggered.connect(self.encrypt_file)

        self.menu_sign = QtGui.QAction("Sign", main_window)
        self.menu_sign.setEnabled(False)
        self.menu_sign.triggered.connect(self.sign)

        self.menu_create_cheaksum = QtGui.QAction("Create cheacksum file", main_window)
        self.menu_create_cheaksum.triggered.connect(self.create_cheaksum)
        

        self.menu_verify_cheaksum = QtGui.QAction("Verify cheacksum file", main_window)
        self.menu_verify_cheaksum.triggered.connect(self.verify_cheaksum)

        self.menu_quit_act = QtGui.QAction("Quit", main_window)
        self.menu_quit_act.setShortcut("Ctrl+Q")
        self.menu_quit_act.triggered.connect(main_window.close)
        self.menu_quit_act.setCheckable(True)

        self.menu_detail = QtGui.QAction("Details", main_window)
        self.menu_detail.setEnabled(False)
        self.menu_detail.triggered.connect(self.details)

        self.menu_certificates_tab = QtGui.QAction("Certificates", main_window)
        self.menu_certificates_tab.triggered.connect(self.certificates_tab)

        self.menu_notepad_tab = QtGui.QAction("Notepad", main_window)
        self.menu_notepad_tab.triggered.connect(self.notepad_tab)

        self.menu_change_password = QtGui.QAction("Change password", main_window)
        self.menu_change_password.triggered.connect(self.menu_change_password_user)
        
        self.menu_change_user = QtGui.QAction("Change User", main_window)
        self.menu_change_user.triggered.connect(self.login)

        self.menu_create_new_account = QtGui.QAction("Create new account", main_window)
        self.menu_create_new_account.triggered.connect(self.menu_registrate_user)

        self.menu_delete_account = QtGui.QAction("Delete this account", main_window)
        self.menu_delete_account.triggered.connect(self.menu_delete_user)


    def createMenu(self, main_window):
        file_menu = main_window.menuBar().addMenu("File")
        file_menu.addAction(self.menu_generate_key_pair)
        file_menu.addSeparator()
        file_menu.addAction(self.menu_import)
        file_menu.addAction(self.menu_export)
        file_menu.addSeparator()
        file_menu.addAction(self.menu_decrypt)
        file_menu.addAction(self.menu_verify)
        file_menu.addAction(self.menu_encrypt)
        file_menu.addAction(self.menu_sign)
        file_menu.addSeparator()
        file_menu.addAction(self.menu_create_cheaksum)
        file_menu.addAction(self.menu_verify_cheaksum)
        file_menu.addSeparator()
        file_menu.addAction(self.menu_quit_act)

        view_menu = main_window.menuBar().addMenu("View")
        view_menu.addAction(self.menu_detail)
        view_menu.addSeparator()
        view_menu.addAction(self.menu_certificates_tab)
        view_menu.addAction(self.menu_notepad_tab)

        cert_menu = main_window.menuBar().addMenu("Certificates")

        account_menu = main_window.menuBar().addMenu("Account settings")
        account_menu.addAction(self.menu_change_password)
        account_menu.addAction(self.menu_change_user)
        account_menu.addAction(self.menu_create_new_account)
        account_menu.addAction(self.menu_delete_account)



    def registrate_user(self):
        try:
            Dialog = QtWidgets.QDialog()
            regist_ui = rg.Registrate_Dialog()
            regist_ui.setupUi(Dialog)
            res = Dialog.exec()
            self.email_user, self.password_user = regist_ui.saveText()
            self.path_to_user_file = cfg.PATH_TO_USER_CERTS.format(user_email=self.email_user)
            CsvHandler(self.path_to_user_file, ["user_id", "name", "email", "key_id", "curve_name", "mod", "isimported",  "created_at", "private_key","public_key_x", "public_key_y"], sep=",", cryptor=aes.AESCipher(self.password_user, self.email_user, "CBC"))
        except Exception:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "Your accaunt isn`t created. Try again.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            self.registrate_user()
        QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", f"You successfully create new account, {self.email_user}!", 
                QtWidgets.QMessageBox.StandardButton.Ok)



    def login(self):
        Dialog = QtWidgets.QDialog()
        login_ui = Login_Dialog()
        login_ui.setupUi(Dialog)
        login_ui.registr.clicked.connect(self.registrate_user)
        res = Dialog.exec()
        if not res:
            return

        self.email_user, self.password_user = login_ui.saveText()
        self.path_to_user_file = cfg.PATH_TO_USER_CERTS.format(user_email=self.email_user)
        if self.email_user == "" or self.password_user == "":
            msg = QtWidgets.QMessageBox()
            msg.setText("Error")
            msg.setInformativeText("Oh no!\nName or email fields are empty.")
            msg.setWindowTitle("Error")
            msg.exec()
            return 

        try:
            if not os.path.exists(self.path_to_user_file):
                raise AttributeError
            file_name = self.path_to_user_file
            with open(file_name, "rb") as f:
                plain_text = f.read()
            if not plain_text:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "File is broken or empty.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return 
            decrypted_text = aes.AESCipher(self.password_user, self.email_user, "CBC").decrypt(plain_text)
        except Exception:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "Password or login is incorrect", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            self.login()
            return
            
        self.csv_handler = CsvHandler(self.path_to_user_file, ["user_id", "name", "email", "key_id", "curve_name", "mod", "isimported", "created_at", "private_key","public_key_x", "public_key_y"], sep=",", cryptor=aes.AESCipher(self.password_user, self.email_user, "CBC"))
        self.select_cert_by_email()


    def select_cert_by_email(self):
        self.cert_table.clearContents()
        self.cert_table.setRowCount(1)
        result = self.csv_handler.read([ "user_id", "name", "email","key_id", "isimported"]).to_dict()
        for each in result['user_id']:
            self.add_row(result['name'][each], result['email'][each], result['user_id'][each], result["key_id"][each], result["isimported"][each])


    """def select_cert_by_email(self):
        self.cert_table.clearContents()
        self.cert_table.setRowCount(1)
        result = self.csv_handler.find_entry_by('email', self.email_user).to_dict()
        for each in result['user_id']:
            self.add_row(result['name'][each], self.email_user, result['user_id'][each], result["key_id"][each], result["isimported"][each])"""


    def change_enabled(self, button):
        selected_rows = self.cert_table.selectionModel().selectedRows()
        if len(selected_rows) and selected_rows[0].data() is not None:
            return button.setEnabled(True) 
        button.setEnabled(False)

        
    def change_enable_export(self):
        self.change_enabled(self.Export)

    def change_enable_sign(self):
        self.change_enabled(self.Sign)

    def change_enable_encrypt(self):
        self.change_enabled(self.Encrypt)


    def change_enable_share_email(self):
        self.change_enabled(self.share_email)

    def change_enable_menu_export(self):
        self.change_enabled(self.menu_export)

    def change_enable_menu_sign(self):
        self.change_enabled(self.menu_sign)

    def change_enable_menu_encrypt(self):
        self.change_enabled(self.menu_encrypt)

    def change_enable_menu_detail(self):
        self.change_enabled(self.menu_detail)

    def certificates_tab(self):
        self.tabWidget.setCurrentIndex(0)

    def notepad_tab(self):
        self.tabWidget.setCurrentIndex(1)

    def menu_registrate_user(self):
        self.registrate_user()
        self.login()

    def menu_change_password_user(self):
        Dialog = QtWidgets.QDialog()
        ui = UiChangePassword()
        ui.setupUi(Dialog)
        res = Dialog.exec()
        old_password, new_password = ui.saveText()
        try:
            old_cryptor = aes.AESCipher(old_password, self.email_user, "CBC")
            self.csv_handler = CsvHandler(self.path_to_user_file, ["user_id", "name", "email", "key_id", "curve_name", "mod", "isimported",  "created_at", "private_key","public_key_x", "public_key_y"], sep=",", cryptor=aes.AESCipher(new_password, self.email_user, "CBC"), old_cryptor=old_cryptor)
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", "You successfully change password", 
                QtWidgets.QMessageBox.StandardButton.Ok)
        except Exception:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "Old password is incorrect", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            self.menu_change_password_user()


    def menu_delete_user(self):
        os.remove(self.path_to_user_file)
        QtWidgets.QMessageBox.information(
                self.MainWindow, "Deleting Account", f"You successfully delete your account, {self.email_user}!", 
                QtWidgets.QMessageBox.StandardButton.Ok)
        self.MainWindow.close()
        MainWindow = QtWidgets.QMainWindow()
        ui.setupUi(MainWindow)
        MainWindow.show()

        



    def change_user_choice(self):
        try:
            data = self.cert_table.selectionModel().selectedRows()[0]
            row = self.csv_handler.find_entry_by("key_id", data.siblingAtColumn(4).data(), ["user_id","name","email","key_id","curve_name","mod","isimported","created_at", "public_key_x","public_key_y", "private_key"]).iloc[0].to_dict()
            self.name = row["name"]
            self.user_id = row["user_id"]
            self.email = row["email"]
            self.key_id = row["key_id"]
            self.curve_name = row["curve_name"]
            self.mod = row["mod"]
            self.is_imported = row["isimported"]
            self.valid_from = row["created_at"]
            self.public_key = [row["public_key_x"], row["public_key_y"]]
            self.private_key = row["private_key"]
        except IndexError:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "Choose or create cretificate!", 
                QtWidgets.QMessageBox.StandardButton.Ok)


    def details(self):
        self.change_user_choice()
        expires_in = 365 - int((datetime.datetime.today() - datetime.datetime.strptime(self.valid_from, "%d-%m-%Y")).days)
        Dialog = QtWidgets.QDialog()
        ui = Ui_Details()
        ui.setupUi(Dialog)
        ui.fill_label(self.email, self.name, self.user_id, self.valid_from, expires_in, self.curve_name, self.key_id, self.is_imported)
        ui.export_2.clicked.connect(self.export_cert)
        res = Dialog.exec()


    def share_by_email(self):
        Dialog = QtWidgets.QDialog()
        ui = ShareEmail()
        ui.setupUi(Dialog)
        res = Dialog.exec()
        email_recipient = ui.save_email()
        if not email_recipient:
            return
        data = self.cert_table.selectionModel().selectedRows()[0]

        creating_passprs = QtWidgets.QDialog()
        ui = UiCreatePassphrase()
        ui.setupUi(creating_passprs)
        res = creating_passprs.exec()
        passphrase = ui.saveText()
        
        try:
            text = self.csv_handler.find_entry_by("key_id", data.siblingAtColumn(4).data(), ["user_id","name","email","key_id","curve_name","mod", "created_at", "public_key_x","public_key_y"]).iloc[0].tolist()
            file_name = f"Certificate_to_{email_recipient}.asc"
            text = ", ".join(map(str, text))
            if passphrase == "":
                with open(file_name, "w") as f:   
                    f.write(text)
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Seccess", "You have successfully exported", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                
            else:
                encrypted_text = aes.AESCipher(str(passphrase), str(passphrase), "CBC").encrypt(text).decode('utf-8')
                with open(file_name, "w") as f:   
                    f.write(encrypted_text)
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Seccess", "You have successfully exported and secured your certificate with a passphrase.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
        except Exception:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Not Saved", "Cerificate does not save. Try Again.", 
            QtWidgets.QMessageBox.StandardButton.Ok)
            return
        try:
            share_certificate_via_email(email_recipient, certificate_owner=self.email_user, certificate=file_name)
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Sharing success", "Email successfully send.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
        except Exception as err:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Sharing error", "Email does not send. Try Again.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            return
        


    def create_cheaksum(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "*")

        if file_name:
            with open(file_name, "rb") as f:
                text_to_hash = f.read()
            hash_text = hashlib.sha256(text_to_hash).hexdigest()
            hash_text = f"{hash_text}, {file_name}"
            
            with open(f"{file_name}_sha256.txt", "w") as fw:
                fw.write(hash_text)

            QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", "Нou have successfully created HashSum SHA256!", 
            QtWidgets.QMessageBox.StandardButton.Ok)


    def verify_cheaksum(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "*")

        if file_name.endswith("_sha256.txt"):
            with open(file_name, "r") as f:
                text = f.read().split(", ")
            hash_from_file = text[0]
            path_to_file = text[1]
            with open(path_to_file, "rb") as f:
                text_to_hash = f.read()
            hash_of_file = hashlib.sha256(text_to_hash).hexdigest()
            if hash_of_file == hash_from_file:
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Seccess", "Hashes matched. The file has not been modified.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            elif hash_of_file != hash_from_file:
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Fail", "Hashes did not match. The file has been modified.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
        elif not file_name:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Fail", "Choose file with hashsum to verify.", 
            QtWidgets.QMessageBox.StandardButton.Ok)
        elif not file_name.endswith("_sha256.txt"):
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Fail", "Choose file with hashsum to verify. Files end with '_sha256'!", 
            QtWidgets.QMessageBox.StandardButton.Ok)
            self.verify_cheaksum()

            

      
    def import_cert(self):
        
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "Cetificate Files (*.asc)")
        cheacking_passprs = QtWidgets.QDialog()
        ui = UiCheakingPassphrase()
        ui.setupUi(cheacking_passprs)
        res = cheacking_passprs.exec()
        passphrase = ui.save_passphrase()

        if file_name:
            with open(file_name, "r") as f:
                    import_cert_text = f.read()
            if passphrase == "":
                pass
            if not import_cert_text:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "File is broken or empty.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return 
            else:
                try:
                    import_cert_text = aes.AESCipher(str(passphrase), str(passphrase), "CBC").decrypt(import_cert_text).decode('utf-8')
                except Exception:
                    QtWidgets.QMessageBox.information(
                        self.MainWindow, "Failed", "Passphrase is incorrect", 
                    QtWidgets.QMessageBox.StandardButton.Ok)
                    return
            data = import_cert_text.split(", ")
            self.is_imported = "True"
            if  self.csv_handler.find_entry_by("key_id", data[3],["user_id","key_id"]).empty:
                self.add_row(data[1], data[2], data[0], data[3], self.is_imported)

                self.csv_handler.append({
                "user_id": data[0],
                "name": data[1],
                "email": data[2],
                "key_id": data[3],
                "curve_name":  data[4],
                "mod": data[5],
                "isimported": self.is_imported,
                "created_at": data[6],
                "private_key": None,
                "public_key_x": data[7],
                "public_key_y": data[8],
            })
            else:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "This Certificate exists", "Certificate already exists", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return 
        
            

    def export_cert(self):

        creating_passprs = QtWidgets.QDialog()
        ui = UiCreatePassphrase()
        ui.setupUi(creating_passprs)
        res = creating_passprs.exec()
        passphrase = ui.saveText()

        data = self.cert_table.selectionModel().selectedRows()[0]
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self.MainWindow, "Save File",
            "","Certificate Files (*.asc)")

        if file_name.endswith(".asc"):
            text = self.csv_handler.find_entry_by("key_id", data.siblingAtColumn(4).data(), ["user_id","name","email","key_id","curve_name","mod", "created_at", "public_key_x","public_key_y"]).iloc[0].tolist()
            text = ", ".join(map(str, text))
            if passphrase == "":
                with open(file_name, "w") as f:   
                    f.write(text)
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Seccess", "You have successfully exported", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                
            else:
                encrypted_text = aes.AESCipher(str(passphrase), str(passphrase), "CBC").encrypt(text).decode('utf-8')
                with open(file_name, "w") as f:   
                    f.write(encrypted_text)
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Seccess", "You have successfully exported and secured your certificate with a passphrase.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                
        else:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Not Saved", "The certificate was not exported.", 
                QtWidgets.QMessageBox.StandardButton.Ok)



    def creating_ecc(self):
        creating_dialog = QtWidgets.QDialog()
        ui = Create_CERT()
        ui.setupUi(creating_dialog)
        res = creating_dialog.exec()
        if not res:
            return
        """if ui.checkBoxPassphrase.isChecked():
            passphrase_dialog = QtWidgets.QDialog()
            ui_passphrase = UiCreatePassphrase()
            ui_passphrase.setupUi(passphrase_dialog)
            res = passphrase_dialog.exec()
            self.passphrase = ui_passphrase.saveText()"""
        
        self.name, self.email, self.curve_name, self.mod = ui.saveText()
        
        if self.name == "" or self.email == "":
            msg = QtWidgets.QMessageBox()
            msg.setText("Error")
            msg.setInformativeText("Oh no!\nName or email fields are empty.")
            msg.setWindowTitle("Error")
            msg.exec()
            return
        
        ecc = ecdhe.ECCKeyGenerator(curve=ecdhe.curves[self.curve_name])
        self.private_key, self.public_key = ecc.gen_keypair()

        self.key_id = shortuuid.uuid()
        self.user_id = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        self.is_imported = "False"
        created_at = date.today().strftime("%d-%m-%Y")
        self.csv_handler.append({
            "user_id": self.user_id,
            "name": self.name,
            "email": self.email,
            "key_id": self.key_id,
            "curve_name":  self.curve_name,
            "mod": self.mod,
            "isimported": self.is_imported,
            "created_at": created_at, 
            "private_key": self.private_key,
            "public_key_x": self.public_key[0],
            "public_key_y": self.public_key[1],
        })

        self.add_row(self.name, self.email, self.user_id, self.key_id, self.is_imported)
        

    def add_row(self, name, email, user_id, key_id, isimported):
        self.row_count = self.cert_table.rowCount()

        new_name_item = QtWidgets.QTableWidgetItem(str(name))
        self.cert_table.setItem(self.row_count - 1, 0, new_name_item)
        new_email_items = QtWidgets.QTableWidgetItem(str(email))
        self.cert_table.setItem(self.row_count - 1, 1, new_email_items)
        new_imported_items = QtWidgets.QTableWidgetItem(str(isimported))
        self.cert_table.setItem(self.row_count - 1, 2, new_imported_items)
        new_userid_items = QtWidgets.QTableWidgetItem(str(user_id))
        self.cert_table.setItem(self.row_count - 1, 3, new_userid_items)
        new_keyid_items = QtWidgets.QTableWidgetItem(str(key_id))
        self.cert_table.setItem(self.row_count - 1, 4, new_keyid_items)

        self.cert_table.setRowCount(self.row_count + 1)     


    def encrypt_note_aes(self):
        if self.check_notepad() == True:
            self.textEdit.setText(aes.AESCipher(str(self.public_key[0]), str(self.public_key[1]), self.mod).encrypt(self.textEdit.toPlainText()).decode('utf-8'))


    def decrypt_note_aes(self):
        if self.check_notepad() == True:
            self.textEdit.setText(aes.AESCipher(str(self.public_key[0]), str(self.public_key[1]), self.mod).decrypt(self.textEdit.toPlainText()).decode('utf-8'))


    def check_notepad(self):
        if self.textEdit.toPlainText() == "" :
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Empty notepad", "Please, enter text.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            return 
        elif self.public_key[0] == "" or self.public_key[0] == None:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "No sertificates", "Please, create certificates.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            return 
        return True


    def encrypt_file(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "*")

        if file_name:
            with open(file_name, "rb") as f:
                plain_text = f.read()
            if not plain_text:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "File is broken or empty.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return 
            
            encrypted_text = aes.AESCipher(str(self.public_key[0]), str(self.public_key[1]), self.mod).encrypt(plain_text).decode('utf-8')
            with open(f"{file_name}.enc", "wb") as fw:
                fw.write(encrypted_text.encode())

            QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", "You have successfully encrypted the file!", 
            QtWidgets.QMessageBox.StandardButton.Ok)

        
    def decrypt_file(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "Encrypted Files *.enc")

        if file_name:
            with open(file_name, "rb") as f:
                plain_text = f.read()
            if not plain_text:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "File is broken or empty.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return 
            try:
                decrypted_text = aes.AESCipher(str(self.public_key[0]), str(self.public_key[1]), self.mod).decrypt(plain_text)
            except Exception:
                QtWidgets.QMessageBox.information(
                    self.MainWindow, "Failed", "You can not decrypt file.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return
            with open(f"{file_name[:-4]}", "wb") as fw:
                fw.write(decrypted_text)

            QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", "You have successfully decrypted the file!", 
            QtWidgets.QMessageBox.StandardButton.Ok)


    def sign(self):
        if self.is_imported:
            QtWidgets.QMessageBox.information(
                self.MainWindow, "Failed", "You cannot use an imported certificate to create your own signature.", 
            QtWidgets.QMessageBox.StandardButton.Ok)
            return

        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "*")

        if file_name:
            with open(file_name, "rb") as f:
                plain_text = f.read()
            if not plain_text:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Error", "File is broken or empty.", 
                QtWidgets.QMessageBox.StandardButton.Ok)
                return 
            
            signature = sgn.sign_message(self.private_key, plain_text, ecdhe.DEFAULT_ELLIPTIC_CURVE)
            
            with open(f"{file_name}.sgn", "w") as fw:
                fw.write(", ".join(map(str, signature)))

            QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", "You have successfully signed the file!", 
            QtWidgets.QMessageBox.StandardButton.Ok)


    def verify_sign(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.MainWindow, "Open File", "", 
            "Signed Files *.sgn")
        
        if file_name:
            with open(file_name, "r") as f:
                signature = f.read()

            with open(file_name[:-4], "rb") as f:
                plain_text = f.read()
            try:
                result = sgn.verify_signature(list(map(int, self.public_key)), plain_text, list(map(int, signature.split(", "))), ecdhe.DEFAULT_ELLIPTIC_CURVE)
            except Exception:
                result = 0
                pass
            if result == "signature matches":
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Seccess", f"Seccess! Signature matches. Signatory: {self.name}", 
                QtWidgets.QMessageBox.StandardButton.Ok)
            else:
                QtWidgets.QMessageBox.information(
                self.MainWindow, "Failed", "Failed... Invalid signature", 
                QtWidgets.QMessageBox.StandardButton.Ok)



    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "ELLICE"))

        item = self.cert_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Name"))
        item = self.cert_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Email"))
        item = self.cert_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "IsImported"))
        item = self.cert_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "User-ID"))
        item = self.cert_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Key-ID"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.certificates), _translate("MainWindow", "Certificates"))
        self.Decryptnotepad.setText(_translate("MainWindow", "Decrypt Notepad"))
        self.encryptnotepad.setText(_translate("MainWindow", "Encrypt Notepad"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Notepad"))
        self.Create_keys.setText(_translate("MainWindow", "Create keys"))
        self.Encrypt.setText(_translate("MainWindow", "Encrypt"))
        self.Decrypt.setText(_translate("MainWindow", "Decrypt"))
        self.Import.setText(_translate("MainWindow", "Import"))
        self.Export.setText(_translate("MainWindow", "Export"))
        self.Sign.setText(_translate("MainWindow", "Sign"))
        self.Verify.setText(_translate("MainWindow", "Verify"))
        self.share_email.setText(_translate("MainWindow", "Share cert\n via Email"))



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
