# -*- coding: utf-8 -*-
"""
widgets.py —— 自定义控件：文件拖拽区 DropArea

单独成模块的原因：它需要在 gui.ui 中通过「提升窗口部件(Promoted Widget)」被引用，
若放在 app/gui.py 内，uic 加载 .ui 时会与 app.gui 产生循环导入。
"""

import os

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QFileDialog, QLabel, QMessageBox


class DropArea(QLabel):
    """文件拖拽区：支持拖拽与点击选择，载入后发出 fileLoaded 信号。

    构造签名与 QLabel 保持一致（首个参数为 parent），
    以便 Qt 的 uic 在加载 .ui 时按 ``DropArea(parent)`` 实例化。
    """

    fileLoaded = pyqtSignal(str, bytes)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self._reset_style()

    def _reset_style(self):
        self.setStyleSheet(
            "QLabel { border: 2px dashed rgba(53, 167, 255, 150); border-radius: 10px;"
            " color: #9CC3E8; padding: 8px; background: rgba(53, 167, 255, 8%); }"
        )

    def _loaded_style(self):
        self.setStyleSheet(
            "QLabel { border: 2px solid #1DC981; border-radius: 10px;"
            " color: #E6F1FF; padding: 8px; background: rgba(29, 201, 129, 12%); }"
        )

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            self.load_path(urls[0].toLocalFile())

    def mousePressEvent(self, event):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            self.load_path(path)

    def load_path(self, path: str):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            QMessageBox.warning(self, "读取失败", f"无法读取文件：\n{exc}")
            return
        name = os.path.basename(path)
        self.setText(f"📄 {name}\n{len(data):,} 字节")
        self._loaded_style()
        self.fileLoaded.emit(name, data)
