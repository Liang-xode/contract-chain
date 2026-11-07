# -*- coding: utf-8 -*-
"""
dialogs.py —— 统一深色中文风格对话框封装

把散落在 gui.py 各处的 QMessageBox 调用集中到这里，统一深色主题与中文按钮文案，
避免原生 QMessageBox 在深色背景下出现浅色/不可读的样式割裂。

对外提供：
    confirm(parent, title, text) -> bool   双按钮：确认 / 取消，返回是否点了「确认」
    warn(parent, title, text)               单按钮：确认，用于警示提示（无交互选择）
    info(parent, title, text)               单按钮：确认，用于普通提示
    ChangePasswordDialog(parent)            修改密码独立弹窗（原密码/新密码/确认新密码）
"""

from PyQt5.QtWidgets import (
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

# 与主窗口深色科技主题一致的弹窗样式：深蓝底、浅色文字、圆角按钮
_DIALOG_QSS = """
QMessageBox {
    background-color: #0A1E42;
}
QMessageBox QLabel {
    color: #E6F1FF;
    font-size: 13px;
    min-width: 320px;
}
QMessageBox QPushButton {
    background-color: #1DC981;
    color: #02121f;
    font-weight: bold;
    padding: 6px 20px;
    border-radius: 4px;
    min-width: 80px;
}
QMessageBox QPushButton:hover {
    background-color: #21C8F6;
}
QMessageBox QPushButton:default {
    background-color: #3E7BFA;
    color: #FFFFFF;
}
"""


def _make_box(parent, title, text, icon=QMessageBox.Warning):
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(icon)
    box.setStyleSheet(_DIALOG_QSS)
    return box


def confirm(parent, title, text) -> bool:
    """确认弹窗：双按钮「确认 / 取消」，返回 True 表示用户点击了确认。"""
    box = _make_box(parent, title, text, QMessageBox.Question)
    yes_btn = box.addButton("确认", QMessageBox.YesRole)
    box.addButton("取消", QMessageBox.NoRole)
    box.setDefaultButton(yes_btn)
    box.exec_()
    return box.clickedButton() is yes_btn


def warn(parent, title, text) -> None:
    """警示弹窗：单按钮「确认」。"""
    box = _make_box(parent, title, text, QMessageBox.Warning)
    box.addButton("确认", QMessageBox.AcceptRole)
    box.exec_()


def info(parent, title, text) -> None:
    """普通提示弹窗：单按钮「确认」。"""
    box = _make_box(parent, title, text, QMessageBox.Information)
    box.addButton("确认", QMessageBox.AcceptRole)
    box.exec_()


# ---------------------------------------------------------------- 修改密码弹窗

_FORM_QSS = """
QDialog {
    background-color: #0A1E42;
}
QLabel {
    color: #E6F1FF;
    font-size: 13px;
}
QLineEdit {
    background-color: #10274E;
    color: #E6F1FF;
    border: 1px solid #2E5BBA;
    border-radius: 4px;
    padding: 6px 8px;
    min-height: 24px;
}
QLineEdit:focus {
    border: 1px solid #21C8F6;
}
QPushButton {
    background-color: #1DC981;
    color: #02121f;
    font-weight: bold;
    padding: 6px 20px;
    border-radius: 4px;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #21C8F6;
}
QPushButton#btn_cancel {
    background-color: #2E5BBA;
    color: #FFFFFF;
}
QPushButton#btn_cancel:hover {
    background-color: #3E7BFA;
}
"""


class ChangePasswordDialog(QDialog):
    """修改密码独立弹窗：原密码 / 新密码 / 确认新密码 + 前端校验。

    用法：
        dlg = ChangePasswordDialog(parent)
        if dlg.exec_() == QDialog.Accepted:
            old, new = dlg.values()
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("修改密码")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.setStyleSheet(_FORM_QSS)
        self._old_pwd = None
        self._new_pwd = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        title = QLabel("修改登录密码")
        title.setStyleSheet("font-size:16px; font-weight:bold; color:#21C8F6;")
        root.addWidget(title)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)

        self.edt_old = QLineEdit()
        self.edt_old.setEchoMode(QLineEdit.Password)
        self.edt_old.setPlaceholderText("请输入当前密码")
        self.edt_new = QLineEdit()
        self.edt_new.setEchoMode(QLineEdit.Password)
        self.edt_new.setPlaceholderText("至少 6 位")
        self.edt_new2 = QLineEdit()
        self.edt_new2.setEchoMode(QLineEdit.Password)
        self.edt_new2.setPlaceholderText("再次输入新密码")

        for row, (text, edt) in enumerate((
                ("原密码", self.edt_old),
                ("新密码", self.edt_new),
                ("确认新密码", self.edt_new2))):
            grid.addWidget(QLabel(text), row, 0)
            grid.addWidget(edt, row, 1)
        root.addLayout(grid)

        self.lbl_msg = QLabel("")
        self.lbl_msg.setWordWrap(True)
        self.lbl_msg.setMinimumHeight(20)
        self.lbl_msg.setStyleSheet("color:#E8463A;")
        root.addWidget(self.lbl_msg)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.btn_cancel = QPushButton("取消")
        self.btn_cancel.setObjectName("btn_cancel")
        self.btn_ok = QPushButton("确认修改")
        self.btn_ok.setDefault(True)
        btn_row.addWidget(self.btn_cancel)
        btn_row.addWidget(self.btn_ok)
        root.addLayout(btn_row)

        self.btn_ok.clicked.connect(self._on_accept)
        self.btn_cancel.clicked.connect(self.reject)
        self.edt_new2.returnPressed.connect(self._on_accept)
        self.edt_old.setFocus()

    def _on_accept(self):
        old = self.edt_old.text().strip()
        new = self.edt_new.text()
        confirm_new = self.edt_new2.text()
        if not old:
            self.lbl_msg.setText("请输入当前密码")
            self.edt_old.setFocus()
            return
        if len(new) < 6:
            self.lbl_msg.setText("新密码至少 6 位")
            self.edt_new.setFocus()
            return
        if new != confirm_new:
            self.lbl_msg.setText("两次输入的新密码不一致")
            self.edt_new2.setFocus()
            return
        self.lbl_msg.setText("")
        self._old_pwd = old
        self._new_pwd = new
        self.accept()

    def values(self):
        """返回 (原密码, 新密码)。"""
        return self._old_pwd, self._new_pwd
