# -*- coding: utf-8 -*-
"""
login.py —— 登录 / 注册对话框

界面外观定义在同目录的 login.ui 中（可用 Qt Designer 直接打开修改），
本文件只负责校验、调用业务层并维护登录态。

登录成功后，FileEvidenceService 内部会持有当前用户（current_user），
后续存证记录的 uploader_id 即归属该账号；密码仅以 PBKDF2 加盐哈希入库。

自助注册仅创建普通用户；管理员账号不在界面开放，需由系统在后台预先配置。
"""

import os
import sys
import warnings

# 与 gui.py 一致：过滤 PyQt5 在 Python 3.11+ 的 sipPyTypeDict 弃用告警
warnings.filterwarnings("ignore", message="sipPyTypeDict")

try:
    from PyQt5 import uic
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QColor, QLinearGradient, QPainter, QPixmap
    from PyQt5.QtWidgets import QApplication, QDialog
except ImportError as exc:  # 缺少 GUI 依赖时给出可执行提示
    sys.stderr.write(
        "未检测到 PyQt5，无法启动登录界面。\n"
        "请先安装依赖：pip install PyQt5\n"
    )
    raise SystemExit(1) from exc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LOGIN_UI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "login.ui")
LOGIN_BG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "assets", "login_bg.png")

ERROR_STYLE = "color: #E8463A;"
OK_STYLE = "color: #1DC981;"


class LoginDialog(QDialog):
    """登录对话框：成功时 self.user 为业务层返回的用户信息（dict）。"""

    def __init__(self, svc, parent=None):
        super().__init__(parent)
        uic.loadUi(LOGIN_UI_PATH, self)   # 加载后 .ui 中的具名控件成为本实例属性

        # 登录页背景：优先使用 assets/login_bg.png，缺失时回退为深色科技渐变
        self._background = QPixmap(LOGIN_BG_PATH)

        self.svc = svc
        self.user = None
        self._last_password = None        # 登录成功时的口令，供主窗口加载本地密钥文件用
        self._bind()
        self._show_login_page()
        self.edt_user.setFocus()

    # ------------------------------------------------------------- 背景绘制
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

        if not self._background.isNull():
            scaled = self._background.scaled(
                self.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
            x = (self.width() - scaled.width()) // 2
            y = (self.height() - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)
        else:
            fallback = QLinearGradient(0, 0, self.width(), self.height())
            fallback.setColorAt(0.0, QColor("#050D1F"))
            fallback.setColorAt(0.5, QColor("#0A1E42"))
            fallback.setColorAt(1.0, QColor("#04101F"))
            painter.fillRect(self.rect(), fallback)

        # 横向渐变遮罩：左侧保留主视觉，右侧压暗以突出登录卡片
        shade = QLinearGradient(0, 0, self.width(), 0)
        shade.setColorAt(0.0, QColor(3, 8, 22, 55))
        shade.setColorAt(0.55, QColor(3, 8, 22, 120))
        shade.setColorAt(1.0, QColor(3, 8, 22, 212))
        painter.fillRect(self.rect(), shade)
        painter.end()

    # ------------------------------------------------------------- 信号绑定
    def _bind(self):
        self.btn_login.clicked.connect(self._on_login)
        self.btn_to_register.clicked.connect(self._show_register_page)
        self.btn_back.clicked.connect(self._show_login_page)
        self.btn_do_register.clicked.connect(self._on_register)
        self.btn_quit.clicked.connect(self.reject)

        self.edt_pwd.returnPressed.connect(self._on_login)
        self.edt_reg_pwd2.returnPressed.connect(self._on_register)

    # ------------------------------------------------------------- 页面切换
    def _show_login_page(self):
        self.stack.setCurrentWidget(self.page_login)
        self.lbl_login_msg.clear()
        self.lbl_register_msg.clear()
        self.edt_pwd.clear()
        self.edt_user.setFocus()

    def _show_register_page(self):
        self.stack.setCurrentWidget(self.page_register)
        self.lbl_register_msg.clear()
        self.edt_reg_user.setFocus()

    # ------------------------------------------------------------- 登录
    def _on_login(self):
        username = self.edt_user.text().strip()
        password = self.edt_pwd.text()
        if not username or not password:
            self._set_msg(self.lbl_login_msg, "请输入用户名和密码")
            return

        self.btn_login.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.user = self.svc.login(username, password)
        except ValueError as exc:          # 账号不存在 / 口令错误 / 已禁用
            self._set_msg(self.lbl_login_msg, str(exc))
            self.edt_pwd.clear()
            self.edt_pwd.setFocus()
        except Exception as exc:          # 数据库等异常兜底
            self._set_msg(self.lbl_login_msg, f"登录失败：{type(exc).__name__}: {exc}")
        else:
            self._last_password = password   # 登录成功后保存口令，主窗口用它解锁本地密钥文件
            self.accept()
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_login.setEnabled(True)

    # ------------------------------------------------------------- 注册
    def _on_register(self):
        username = self.edt_reg_user.text().strip()
        password = self.edt_reg_pwd.text()
        confirm = self.edt_reg_pwd2.text()

        if not username:
            self._set_msg(self.lbl_register_msg, "请输入用户名")
            return
        if len(username) > 64:
            self._set_msg(self.lbl_register_msg, "用户名不能超过 64 个字符")
            return
        if not password:
            self._set_msg(self.lbl_register_msg, "请输入密码")
            return
        if password != confirm:
            self._set_msg(self.lbl_register_msg, "两次输入的密码不一致")
            self.edt_reg_pwd2.clear()
            self.edt_reg_pwd2.setFocus()
            return

        role = "user"                  # 自助注册一律为普通用户；管理员账号不在此开放
        self.btn_do_register.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.svc.register_user(username, password, role=role,
                                   display_name=username)
        except ValueError as exc:          # 用户名重复等业务校验
            self._set_msg(self.lbl_register_msg, str(exc))
        except Exception as exc:
            self._set_msg(self.lbl_register_msg, f"注册失败：{type(exc).__name__}: {exc}")
        else:
            # 注册成功后回到登录页，预填用户名，避免口令残留
            self.edt_reg_user.clear()
            self.edt_reg_pwd.clear()
            self.edt_reg_pwd2.clear()
            self.edt_user.setText(username)
            self.stack.setCurrentWidget(self.page_login)
            self._set_msg(self.lbl_login_msg, f"注册成功，请使用 {username} 登录", ok=True)
            self.edt_pwd.clear()
            self.edt_pwd.setFocus()
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_do_register.setEnabled(True)

    # ------------------------------------------------------------- 小工具
    @staticmethod
    def _set_msg(label, text, ok=False):
        label.setText(text)
        label.setStyleSheet(OK_STYLE if ok else ERROR_STYLE)
