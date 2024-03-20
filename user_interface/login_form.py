# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'login_form.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(499, 300)
        Form.setStyleSheet("border: none;")
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.widget = QtWidgets.QWidget(Form)
        self.widget.setMinimumSize(QtCore.QSize(400, 0))
        self.widget.setStyleSheet("background-color: rgb(75, 75, 75);")
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.frame_3 = QtWidgets.QFrame(self.widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_3.sizePolicy().hasHeightForWidth())
        self.frame_3.setSizePolicy(sizePolicy)
        self.frame_3.setStyleSheet("background-color: rgb(75, 75, 75);")
        self.frame_3.setObjectName("frame_3")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.frame_3)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.frame_4 = QtWidgets.QFrame(self.frame_3)
        self.frame_4.setMinimumSize(QtCore.QSize(300, 0))
        self.frame_4.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_4.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_4.setObjectName("frame_4")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.frame_4)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_4 = QtWidgets.QLabel(self.frame_4)
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_2.addWidget(self.label_4, 0, QtCore.Qt.AlignHCenter|QtCore.Qt.AlignVCenter)
        self.verticalLayout_2.addWidget(self.frame_4)
        self.frame_5 = QtWidgets.QFrame(self.frame_3)
        self.frame_5.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_5.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_5.setObjectName("frame_5")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.frame_5)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.lineEdit = QtWidgets.QLineEdit(self.frame_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit.sizePolicy().hasHeightForWidth())
        self.lineEdit.setSizePolicy(sizePolicy)
        self.lineEdit.setMinimumSize(QtCore.QSize(300, 0))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.lineEdit.setFont(font)
        self.lineEdit.setStyleSheet("background-color:rgba(0, 0, 0, 0);\n"
"border:none;\n"
"border-bottom: 2px solid rgbargb(255, 255, 255, 210);\n"
"color:rgba(0, 0, 0, 240);\n"
"padding-bottom: 7px;")
        self.lineEdit.setObjectName("lineEdit")
        self.verticalLayout_3.addWidget(self.lineEdit, 0, QtCore.Qt.AlignHCenter)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.frame_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEdit_2.sizePolicy().hasHeightForWidth())
        self.lineEdit_2.setSizePolicy(sizePolicy)
        self.lineEdit_2.setMinimumSize(QtCore.QSize(300, 0))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setStyleSheet("background-color:rgba(0, 0, 0, 0);\n"
"border:none;\n"
"border-bottom: 2px solid rgbargb(255, 255, 255, 210);\n"
"color:rgba(0, 0, 0, 240);\n"
"padding-bottom: 7px;")
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.verticalLayout_3.addWidget(self.lineEdit_2, 0, QtCore.Qt.AlignHCenter)
        self.verticalLayout_2.addWidget(self.frame_5)
        self.frame_6 = QtWidgets.QFrame(self.frame_3)
        self.frame_6.setMinimumSize(QtCore.QSize(0, 0))
        self.frame_6.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_6.setObjectName("frame_6")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.frame_6)
        self.verticalLayout_4.setContentsMargins(9, 9, 9, 9)
        self.verticalLayout_4.setSpacing(6)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.login_pushButton = QtWidgets.QPushButton(self.frame_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.login_pushButton.sizePolicy().hasHeightForWidth())
        self.login_pushButton.setSizePolicy(sizePolicy)
        self.login_pushButton.setMinimumSize(QtCore.QSize(200, 40))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.login_pushButton.setFont(font)
        self.login_pushButton.setStyleSheet("QPushButton#login_pushButton{\n"
"    \n"
"    background-color: rgb(0, 0, 0);\n"
"    color:rgba(255, 255, 255, 210);\n"
"    border-radius: 5px;\n"
"}\n"
"\n"
"QPushButton#login_pushButton:hover{\n"
"    background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 0, 0, 255), stop:1 rgba(139, 139, 139));\n"
"}\n"
"\n"
"QPushButton#login_pushButton:pressed{\n"
"    padding-left:5px;\n"
"    padding-top:5px;\n"
"    background-color: rgba(139, 139, 139);\n"
"}\n"
"")
        self.login_pushButton.setObjectName("login_pushButton")
        self.verticalLayout_4.addWidget(self.login_pushButton)
        self.register_pushButton_2 = QtWidgets.QPushButton(self.frame_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.register_pushButton_2.sizePolicy().hasHeightForWidth())
        self.register_pushButton_2.setSizePolicy(sizePolicy)
        self.register_pushButton_2.setMinimumSize(QtCore.QSize(0, 0))
        self.register_pushButton_2.setMaximumSize(QtCore.QSize(16777215, 16777215))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.register_pushButton_2.setFont(font)
        self.register_pushButton_2.setStyleSheet("QPushButton#register_pushButton_2{\n"
"    \n"
"    background-color: rgb(0, 0, 0);\n"
"    color:rgba(255, 255, 255, 210);\n"
"    border-radius: 5px;\n"
"}\n"
"\n"
"QPushButton#register_pushButton_2:hover{\n"
"    background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 0, 0, 255), stop:1 rgba(139, 139, 139));\n"
"}\n"
"\n"
"QPushButton#register_pushButton_2:pressed{\n"
"    padding-left:5px;\n"
"    padding-top:5px;\n"
"    background-color: rgba(139, 139, 139);\n"
"}\n"
"")
        self.register_pushButton_2.setIconSize(QtCore.QSize(20, 16))
        self.register_pushButton_2.setObjectName("register_pushButton_2")
        self.verticalLayout_4.addWidget(self.register_pushButton_2)
        self.forgotpass_pushButton_3 = QtWidgets.QPushButton(self.frame_6)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.forgotpass_pushButton_3.setFont(font)
        self.forgotpass_pushButton_3.setStyleSheet("QPushButton#forgotpass_pushButton_3{\n"
"    \n"
"    background-color: rgb(0, 0, 0);\n"
"    color:rgba(255, 255, 255, 210);\n"
"    border-radius: 5px;\n"
"}\n"
"\n"
"QPushButton#forgotpass_pushButton_3:hover{\n"
"    background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 0, 0, 255), stop:1 rgba(139, 139, 139));\n"
"}\n"
"\n"
"QPushButton#forgotpass_pushButton_3:pressed{\n"
"    padding-left:5px;\n"
"    padding-top:5px;\n"
"    background-color: rgba(139, 139, 139);\n"
"}\n"
"")
        self.forgotpass_pushButton_3.setIconSize(QtCore.QSize(20, 16))
        self.forgotpass_pushButton_3.setObjectName("forgotpass_pushButton_3")
        self.verticalLayout_4.addWidget(self.forgotpass_pushButton_3)
        self.verticalLayout_2.addWidget(self.frame_6, 0, QtCore.Qt.AlignHCenter|QtCore.Qt.AlignVCenter)
        self.horizontalLayout.addWidget(self.frame_3)
        self.verticalLayout.addWidget(self.widget)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label_4.setText(_translate("Form", "Login"))
        self.lineEdit.setPlaceholderText(_translate("Form", "Username"))
        self.lineEdit_2.setPlaceholderText(_translate("Form", "Password"))
        self.login_pushButton.setText(_translate("Form", "Login"))
        self.register_pushButton_2.setText(_translate("Form", "New User? Register Here!"))
        self.forgotpass_pushButton_3.setText(_translate("Form", "Forgot Password?"))
import icons_rc
import res_rc


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
