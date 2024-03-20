import datetime
import json
import sqlite3
import hashlib

from PyQt5 import QtCore, QtWidgets, uic, QtNetwork
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QMessageBox, QTableWidgetItem

import blockchain.views
import database

import sys
import re
import smtplib
import random
import requests

from django.http import JsonResponse

from blockchain.views import Blockchain
from blockchain.views import Wallet
from user_interface import icons_main

# Creating a connection to sqlite database.
conn = sqlite3.connect('cryptoApp.db')
# Create a cursor
c = conn.cursor()


# Main Application Class
class MainApplication(QtWidgets.QMainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        uic.loadUi("main_application.ui", self)
        self.user_info = None
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.maincontent = self.findChild(QtWidgets.QStackedWidget, "main_body_contents")
        self.homepage_send_button = self.findChild(QtWidgets.QPushButton, "sendButton_page1")
        self.pushButton_3.clicked.connect(lambda: MainApplication.close(self))
        self.pushButton.clicked.connect(lambda: MainApplication.showMaximized(self))
        self.pushButton_2.clicked.connect(lambda: MainApplication.showNormal(self))
        self.Side_Menu_Num = 0

        self.pushButton_5.clicked.connect(lambda: self.side_menu_def_0())

        # Create blockchain object
        self.blockchain = Blockchain()

        # Create wallet object and pass blockchain
        self.user_wallet = Wallet()

        # HOME PAGE
        self.pushButton_7.clicked.connect(self.show_home_page)

        # PROFILE PAGE
        self.pushButton_8.clicked.connect(self.show_profile_page)

        # TRANSACTIONS PAGE
        self.pushButton_9.clicked.connect(self.show_transactions_page)

        # Node Address in Transactions Page
        root_node_text_edit = self.findChild(QtWidgets.QTextEdit, "node_address_page3")
        root_node_text_edit.setPlainText(blockchain.views.root_node)
        font = root_node_text_edit.font()
        font.setPointSize(12)
        root_node_text_edit.setFont(font)
        root_node_text_edit.setAlignment(Qt.AlignCenter)
        root_node_text_edit.setReadOnly(True)

        self.sendTransaction_page3.clicked.connect(self.add_transaction)
        self.refresh_button.clicked.connect(self.refresh_data)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.tableWidget.verticalHeader().setVisible(False)

        # WALLET PAGE
        self.pushButton_11.clicked.connect(self.show_wallet_page)
        self.deposit_pushButton.clicked.connect(self.deposit_crypto)
        self.sell_pushButton.clicked.connect(self.sell_crypto)
        self.sendcrypto_pushButton.clicked.connect(self.send_crypto)

        # LOGOUT
        self.pushButton_10.clicked.connect(self.show_logout)

    def side_menu_def_0(self):
        if self.Side_Menu_Num == 0:
            self.animation1 = QtCore.QPropertyAnimation(self.side_menu_container, b"maximumWidth")
            self.animation1.setDuration(500)
            self.animation1.setStartValue(0)
            self.animation1.setEndValue(300)
            self.animation1.setEasingCurve(QtCore.QEasingCurve.Linear)
            self.animation1.start()

            self.animation2 = QtCore.QPropertyAnimation(self.side_menu_container, b"minimumWidth")
            self.animation2.setDuration(500)
            self.animation2.setStartValue(0)
            self.animation2.setEndValue(300)
            self.animation2.setEasingCurve(QtCore.QEasingCurve.Linear)
            self.animation2.start()

            self.Side_Menu_Num = 1
        else:
            self.animation1 = QtCore.QPropertyAnimation(self.side_menu_container, b"maximumWidth")
            self.animation1.setDuration(500)
            self.animation1.setStartValue(300)
            self.animation1.setEndValue(0)
            self.animation1.setEasingCurve(QtCore.QEasingCurve.Linear)
            self.animation1.start()

            self.animation2 = QtCore.QPropertyAnimation(self.side_menu_container, b"minimumWidth")
            self.animation2.setDuration(500)
            self.animation2.setStartValue(300)
            self.animation2.setEndValue(0)
            self.animation2.setEasingCurve(QtCore.QEasingCurve.Linear)
            self.animation2.start()

            self.Side_Menu_Num = 0

    def show_home_page(self):
        self.maincontent.setCurrentIndex(0)

    def show_profile_page(self):
        self.maincontent.setCurrentIndex(1)

    def show_transactions_page(self):
        self.maincontent.setCurrentIndex(2)

    def show_wallet_page(self):
        self.maincontent.setCurrentIndex(3)

    def show_logout(self):
        UIWindow.hide()
        widget.show()

    def get_user_username(self, username):
        # Replace these values with your database connection details
        db = database.get_db_connection()
        cursor = db.cursor()
        query = "SELECT * FROM `Registration` WHERE `username` = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        db.close()
        return result[0] if result else None

    def get_user_password(self, password):
        # Replace these values with your database connection details
        db = database.get_db_connection()
        cursor = db.cursor()
        query = "SELECT * FROM `Registration` WHERE `password` = %s"
        cursor.execute(query, (password,))
        result = cursor.fetchone()
        cursor.close()
        db.close()
        return result[0] if result else None

    def get_user_email(self, email):
        # Replace these values with your database connection details
        db = database.get_db_connection()
        cursor = db.cursor()
        query = "SELECT * FROM `Registration` WHERE `email` = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        cursor.close()
        db.close()
        return result[0] if result else None

    def display_username(self):
        user_username = self.user_info[0]
        username_widget = self.findChild(QtWidgets.QPlainTextEdit, "username_textEdit_page2")
        username_widget.setPlainText(user_username)
        username_widget.setReadOnly(True)
        font = username_widget.font()
        font.setPointSize(12)
        username_widget.setFont(font)

    def display_password(self):
        user_password = self.user_info[2]
        password_widget = self.findChild(QtWidgets.QPlainTextEdit, "password_textEdit_page2")
        password_widget.setPlainText(user_password)
        password_widget.setReadOnly(True)
        font = password_widget.font()
        font.setPointSize(12)
        password_widget.setFont(font)

    def display_email(self):
        user_email = self.user_info[1]
        email_widget = self.findChild(QtWidgets.QPlainTextEdit, "email_textEdit_page2")
        email_widget.setPlainText(user_email)
        email_widget.setReadOnly(True)
        font = email_widget.font()
        font.setPointSize(12)
        email_widget.setFont(font)

    def refresh_data(self):
        self.show_latest_transactions()
        self.update_mined_blocks_display()

    def get_current_user(self):
        return blockchain.views.root_node

    def is_valid_node_address(self, node_address):
        pattern = r'^[a-fA-F0-9]{64}$'  # 64-character hexadecimal string
        return bool(re.match(pattern, node_address))

    def add_transaction(self):
        url = 'http://127.0.0.1:8000/add_transaction'
        headers = {'Content-type': 'application/json'}
        sender = self.get_current_user()
        receiver = self.recipient_page3.text()
        if not self.is_valid_node_address(receiver):
            print("Invalid node address format.")
            return
        amount = float(self.amount_page3.text())
        time = str(datetime.datetime.now())
        data = {
            'sender': self.get_current_user(),
            'receiver': self.recipient_page3.text(),
            'amount': float(self.amount_page3.text()),
            'time': str(datetime.datetime.now()),
        }
        try:
            response = requests.post(url, json=data, headers=headers)
            response.raise_for_status()
            if response.status_code == 200:
                transaction_success = {'message': 'Transaction successfully added.'}
                print(transaction_success)
            else:
                transaction_fail = {'message': 'Transaction unable to be added.'}
                print(transaction_fail)
        except requests.exceptions.RequestException as e:
            error_message = {'error': str(e)}
            print(error_message)

    def update_mined_blocks(self):
        # Fetch the number of mined blocks (replace with the correct API call)
        response = requests.get('http://127.0.0.1:8000/get_chain')
        num_blocks = response.json()['length']

        return num_blocks
        # Update the QLineEdit widget with the number of mined blocks
        # self.mined_blocks_display.setText(str(num_blocks))

    # Display No. of Current Mined Blocks in Transaction Page
    def update_mined_blocks_display(self):
        num_mined_blocks = self.update_mined_blocks()
        mined_blocks_text_edit = self.findChild(QtWidgets.QTextEdit, "blocks_mined_page3")
        mined_blocks_text_edit.setPlainText(str(num_mined_blocks))
        font = mined_blocks_text_edit.font()
        font.setPointSize(12)
        mined_blocks_text_edit.setFont(font)
        mined_blocks_text_edit.setAlignment(Qt.AlignCenter)
        mined_blocks_text_edit.setReadOnly(True)

    # Display Latest Transactions in Transaction Page
    def show_latest_transactions(self):
        table_widget = self.findChild(QtWidgets.QTableWidget, "tableWidget")

        response = requests.get('http://127.0.0.1:8000/get_pending_transactions')
        transactions = response.json()['transactions']

        print(response.status_code)  # Debug statement
        print(response.text)  # Debug statement

        for i, transaction in enumerate(transactions):
            row_index = table_widget.rowCount()
            table_widget.insertRow(row_index)
            table_widget.setItem(row_index, 0, QTableWidgetItem(transaction['sender']))
            table_widget.setItem(row_index, 1, QTableWidgetItem(transaction['receiver']))
            table_widget.setItem(row_index, 2, QTableWidgetItem(str(transaction['amount'])))
            table_widget.setItem(row_index, 3, QTableWidgetItem(transaction['time']))

        num_rows = table_widget.rowCount()
        row_labels = [str(i) for i in reversed(range(num_rows))]
        table_widget.setVerticalHeaderLabels(row_labels)

    def deposit_crypto(self):
        # Get the amount entered by the user
        amount = float(self.deposit_crypto_lineEdit.text())
        self.deposit_crypto_lineEdit.setText("")

        # Use the deposit_crypto function of the Wallet class to deposit cryptocurrency
        success = self.user_wallet.deposit_crypto(amount)

        if success:
            QMessageBox.information(self, "Success", "Cryptocurrency deposited successfully!")
            # Update the user's balance in the GUI
            self.update_user_balance()
        else:
            QMessageBox.warning(self, "Error", "Failed to deposit cryptocurrency. Please try again.")

    # TODO: Configure function that deposits cryptocurrency on Wallet page.

    def sell_crypto(self):
        # Get the amount entered by the user
        amount = float(self.sell_crypto_lineEdit.text())
        self.deposit_crypto_lineEdit.setText("")

        # Use the deposit_crypto function of the Wallet class to deposit cryptocurrency
        success = self.user_wallet.sell_crypto(amount)

        if success:
            QMessageBox.information(self, "Success", "Cryptocurrency sold successfully!")
            # Update the user's balance in the GUI
            self.update_user_balance()
        else:
            QMessageBox.warning(self, "Error", "Failed to sell cryptocurrency. Please check the amount.")

    def send_crypto(self):
        # Get the recipient's address and amount entered by the user
        recipient_address = self.crypto_recipient_lineEdit.text()
        amount = float(self.crypto_amount_lineEdit.text())
        self.crypto_recipient_lineEdit.setText("")
        self.crypto_amount_lineEdit.setText("")

        # Use the send_crypto function of the Wallet class to send cryptocurrency
        success = self.user_wallet.send_crypto(recipient_address, amount)

        if success:
            QMessageBox.information(self, "Success", "Cryptocurrency sent successfully!")
            # Update the user's balance in the GUI
            self.update_user_balance()
        else:
            QMessageBox.warning(self, "Error",
                                "Failed to send cryptocurrency. Please check the recipient's address and the amount.")

    # TODO: Configure function that updates balance on home page.

    def update_user_balance(self):
        balance = self.user_wallet.get_balance()
        self.balance_display_page1.setText(f"Current Balance: {balance}")
        font = self.balance_display_page1.font()
        font.setPointSize(20)
        self.balance_display_page1.setFont(font)
        self.balance_display_page1.setAlignment(Qt.AlignCenter)
        self.balance_display_page1.setReadOnly(True)

    # TODO: Make Send button on Home page bigger.


# Login Form Class
class LoginApp(QtWidgets.QWidget):
    def __init__(self, main_class_instance):
        super(LoginApp, self).__init__()
        self.MainApplication = main_class_instance
        uic.loadUi("login_form.ui", self)
        self.login_pushButton.clicked.connect(self.login)
        self.register_pushButton_2.clicked.connect(self.show_reg)
        self.forgotpass_pushButton_3.clicked.connect(self.password_reset)

    def login(self):
        username = self.lineEdit.text()
        password = self.lineEdit_2.text()
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        db = database.get_db_connection()
        cursor = db.cursor()
        cursor.execute("select * from Registration where username=%s and password=%s", (username, hashed_password))
        result = cursor.fetchone()
        self.lineEdit.setText("")
        self.lineEdit_2.setText("")

        if result:

            self.MainApplication.user_info = result

            self.MainApplication.display_username()
            self.MainApplication.display_email()
            self.MainApplication.display_password()
            widget.hide()
            UIWindow.show()
        else:
            QMessageBox.information(self, "Login Output", "Invalid User. Please try again.")

    def show_reg(self):
        widget.setCurrentIndex(1)

    def password_reset(self):
        widget.setCurrentIndex(2)


# Registration Form Class
class RegApp(QtWidgets.QWidget):
    def __init__(self):
        super(RegApp, self).__init__()
        uic.loadUi("registration_form.ui", self)
        self.signup_pushButton.clicked.connect(self.reg)
        self.loginredirect_pushButton.clicked.connect(self.show_login)

    def reg(self):
        username = self.username_lineEdit.text()
        email_address = self.email_lineEdit.text()
        password = self.password_lineEdit.text()
        confirm_password = self.confirmpassword_lineEdit.text()
        otp = ''
        password_regex = re.compile(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()-+=]).{8,}$")
        db = database.get_db_connection()
        cursor = db.cursor()
        cursor.execute("select * from Registration where username='" + username + "' and password='" + password + "'")
        result = cursor.fetchone()

        if result:
            QMessageBox.information(self, "Registration Form", "This user has already been registered. Please try "
                                                               "again.")
        else:
            if not password_regex.match(password):
                QMessageBox.information(self, "Registration Form",
                                        "Password must contain at least 8 characters, including one uppercase letter, "
                                        "one lowercase letter, one digit, and one special character.")
            else:
                if password == confirm_password:
                    # Hash Password before insertion into Registration table
                    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
                    cursor.execute("INSERT INTO Registration (username, email, password, otp) VALUES (%s, %s, %s, %s)",
                                   (username, email_address, hashed_password, otp))
                    db.commit()
                    widget.setCurrentIndex(0)
                else:
                    QMessageBox.information(self, "Registration Form", "Passwords do not match. Please try again.")

    def show_login(self):
        widget.setCurrentIndex(0)


# Send OTP Form Class
class SendOTPApp(QtWidgets.QWidget):
    def __init__(self):
        super(SendOTPApp, self).__init__()
        uic.loadUi("generateOTP_form.ui", self)
        self.sendOTP_pushButton.clicked.connect(self.send_otp)
        self.goToLogin_pushButton.clicked.connect(self.go_back_login)

    def send_otp(self):
        email_address = self.email_otp_lineEdit.text()
        smtp_server = "smtp.gmail.com"
        port = 587
        sender_email = "testIndividualSussex1@gmail.com"
        sender_password = "pwqdjnxhglgicxxg"

        server = smtplib.SMTP(smtp_server, port)
        server.starttls()
        server.login(sender_email, sender_password)

        otp = random.randint(100000, 999999)
        otp_int = int(otp)

        message = f"Subject: Password Reset OTP\n\nYour OTP is: {otp}"
        server.sendmail(sender_email, email_address, message)
        server.quit()

        db = database.get_db_connection()
        cursor = db.cursor()
        cursor.execute("select * from Registration where email='" + email_address + "'")
        result = cursor.fetchone()

        if not result:
            QMessageBox.information(self, "Generate OTP", "User doesn't exist. Please try again.")
        else:
            cursor.execute("UPDATE Registration SET otp=%s WHERE email=%s", (str(otp_int), email_address))
            db.commit()
            widget.setCurrentIndex(3)

    def go_back_login(self):
        widget.setCurrentIndex(0)


# Forgot Password Form Class
class ForgotPassApp(QtWidgets.QWidget):
    def __init__(self):
        super(ForgotPassApp, self).__init__()
        uic.loadUi("forgotpassword_form.ui", self)
        self.confirm_pushButton.clicked.connect(self.forgot_pass)
        self.goToGenerate_pushButton.clicked.connect(self.go_back_otp)

    def forgot_pass(self):
        otp = self.otp_passreset_lineEdit.text()
        new_password = self.new_password_lineEdit.text()
        confirm_new_password = self.confirm_new_lineEdit_2.text()
        password_regex = re.compile(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()-+=]).{8,}$")
        db = database.get_db_connection()
        cursor = db.cursor()
        cursor.execute("select * from Registration where otp='" + otp + "'")
        result = cursor.fetchone()

        if not result:
            QMessageBox.information(self, "Registration Form", "Incorrect OTP. Please try again.")
        else:
            if not password_regex.match(new_password):
                QMessageBox.information(self, "Registration Form",
                                        "Password must contain at least 8 characters, including one uppercase letter, "
                                        "one lowercase letter, one digit, and one special character.")
            else:
                if new_password == confirm_new_password:
                    hashed_confirm_new_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
                    cursor.execute("UPDATE Registration SET password=%s WHERE otp=%s", (hashed_confirm_new_password, otp))
                    db.commit()
                    widget.setCurrentIndex(0)
                else:
                    QMessageBox.information(self, "Registration Form", "Passwords do not match. Please try again.")

    def go_back_otp(self):
        widget.setCurrentIndex(2)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = QtWidgets.QStackedWidget()
    UIWindow = MainApplication()
    loginForm = LoginApp(UIWindow)
    registrationForm = RegApp()
    generate_OTPForm = SendOTPApp()
    forgot_passwordForm = ForgotPassApp()
    widget.addWidget(loginForm)
    widget.addWidget(registrationForm)
    widget.addWidget(generate_OTPForm)
    widget.addWidget(forgot_passwordForm)
    widget.setCurrentIndex(0)
    widget.setFixedWidth(1000)
    widget.setFixedHeight(650)
    UIWindow.setFixedWidth(1250)
    UIWindow.setFixedHeight(850)
    widget.show()
    #UIWindow.show()
    app.exec_()
