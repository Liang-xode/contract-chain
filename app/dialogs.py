# -*- coding: utf-8 -*-
"""
dialogs.py —— 统一深色中文风格对话框封装

把散落在 gui.py 各处的 QMessageBox 调用集中到这里，统一深色主题与中文按钮文案，
避免原生 QMessageBox 在深色背景下出现浅色/不可读的样式割裂。

对外提供：
    confirm(parent, title, text) -> bool   双按钮：确认 / 取消，返回是否点了「确认」
    warn(parent, title, text)               单按钮：确认，用于警示提示（无交互选择）
    info(parent, title, text)               单按钮：确认，用于普通提示
"""

from PyQt5.QtWidgets import QMessageBox

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
