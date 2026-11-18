# -*- coding: utf-8 -*-
"""
gui.py —— PyQt5 桌面界面：国密区块链通用电子文件加密存证系统

界面外观定义在同目录的 gui.ui 中（可用 Qt Designer 直接打开修改），
本文件只负责业务逻辑与信号绑定。

功能：
    0. 启动时先弹出登录框（login.ui），支持注册新账号；登录成功才进入主界面
    1. 文件拖拽上传（或点击选择），自动计算并显示 SM3 指纹
    2. 一键签署并上链，分步展示 SM2 签名过程（指纹 → 载荷 → 签名 → 共识上链）
    3. 验真页：三重校验结果以红绿图标区分，内置「篡改 / 伪造签名」攻击演示
    4. 底部实时日志栏输出每一步操作（与上方内容之间有可拖动分隔条）

运行（任选其一）：
    python -m app.gui      # 在项目根目录执行（推荐）
    python app/gui.py      # 直接运行脚本文件
    双击项目根目录的 run_gui.bat
"""

import os
import sys
import time
import warnings

# PyQt5 5.15 在 Python 3.11+ 下会对每个 PyQt 子类抛出 sipPyTypeDict 弃用告警，
# 属上游已知噪音；过滤必须在导入/定义任何 PyQt 子类之前生效。
warnings.filterwarnings("ignore", message="sipPyTypeDict")

try:
    from PyQt5 import uic
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPixmap
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QPlainTextEdit,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # 缺少 GUI 依赖时给出可执行提示，而非直接抛栈
    sys.stderr.write(
        "未检测到 PyQt5，无法启动图形界面。\n"
        "请先安装依赖：pip install PyQt5\n"
        "（或运行项目根目录的 run_gui.bat，会自动补装）\n"
    )
    raise SystemExit(1) from exc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import crypto as cc
from crypto.crypto import KeyStore
from blockchain.chain import EvidenceChain
from app import config
from app import dialogs
from app import report_export
from app.login import LoginDialog
from app.service import FileEvidenceService

UI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui.ui")

OK_ICON = "✅"
BAD_ICON = "❌"
GREEN = "#1DC981"
RED = "#E8463A"
GRAY = "#8A8A93"

ROLE_NAMES = {"superadmin": "超级管理员", "admin": "管理员", "user": "普通用户"}
STATUS_NAMES = {"enabled": "启用", "disabled": "禁用"}


def now_ts() -> str:
    return time.strftime("%H:%M:%S")


def short(text: str, head: int, tail: int) -> str:
    """长 hex 串截断显示：保留首尾，中间省略。"""
    if text and len(text) > head + tail + 3:
        return f"{text[:head]}…{text[-tail:]}"
    return text


class Worker(QThread):
    """后台工作线程：耗时操作（如大文件 SM3 哈希）不阻塞界面。"""

    ok = pyqtSignal(object)
    fail = pyqtSignal(str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            self.ok.emit(self._fn())
        except Exception as exc:  # 界面层兜底，异常写入日志
            self.fail.emit(f"{type(exc).__name__}: {exc}")


class PassphraseDialog(QDialog):
    """存证授权口令输入对话框：口令至少 6 位，输入过程即时校验，确定/取消。"""

    MIN_LEN = 6

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("存证授权口令")
        self.setModal(True)
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)

        tip = QLabel(
            "请设置本次存证的授权口令（至少 6 位）。\n"
            "该口令经 PBKDF2 派生 SM4 会话密钥加密原文，且不落库；"
            "后续「授权解密」必须输入同一口令。")
        tip.setWordWrap(True)
        layout.addWidget(tip)

        row = QHBoxLayout()
        row.addWidget(QLabel("口令："))
        self.edt_passphrase = QLineEdit()
        self.edt_passphrase.setEchoMode(QLineEdit.Password)
        self.edt_passphrase.setPlaceholderText("至少 6 位")
        row.addWidget(self.edt_passphrase, 1)
        layout.addLayout(row)

        self.lbl_msg = QLabel("")
        self.lbl_msg.setWordWrap(True)
        self.lbl_msg.setMinimumHeight(20)
        layout.addWidget(self.lbl_msg)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.btn_ok = QPushButton("确定")
        self.btn_ok.setDefault(True)
        self.btn_ok.setEnabled(False)          # 长度达标前不可提交
        self.btn_cancel = QPushButton("取消")
        btn_row.addWidget(self.btn_ok)
        btn_row.addWidget(self.btn_cancel)
        layout.addLayout(btn_row)

        self.edt_passphrase.textChanged.connect(self._on_text_changed)
        self.edt_passphrase.returnPressed.connect(self._on_accept)
        self.btn_ok.clicked.connect(self._on_accept)
        self.btn_cancel.clicked.connect(self.reject)

    def _on_text_changed(self, text):
        ok = len(text) >= self.MIN_LEN
        self.btn_ok.setEnabled(ok)
        if not text:
            self.lbl_msg.clear()
        elif ok:
            self.lbl_msg.setText(f"✅ 口令长度 {len(text)} 位")
            self.lbl_msg.setStyleSheet(f"color:{GREEN};")
        else:
            self._warn_short(text)

    def _warn_short(self, text):
        self.lbl_msg.setText(f"⚠ 口令至少 {self.MIN_LEN} 位，当前 {len(text)} 位")
        self.lbl_msg.setStyleSheet(f"color:{RED};")

    def _on_accept(self):
        text = self.edt_passphrase.text()
        if len(text) < self.MIN_LEN:
            self._warn_short(text)
            self.edt_passphrase.setFocus()
            return
        self.accept()

    def passphrase(self) -> str:
        return self.edt_passphrase.text()


class ResetPasswordDialog(QDialog):
    """管理员代重置密码对话框：默认新密码 123456（可直接提交），支持改填 + 二次确认，至少 6 位。"""

    MIN_LEN = 6
    DEFAULT_PASSWORD = "123456"

    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"重置密码 · {username}")
        self.setModal(True)
        self.setMinimumWidth(440)
        self._username = username

        layout = QVBoxLayout(self)

        tip = QLabel(
            f"将为账号「{username}」设置新的登录密码（至少 {self.MIN_LEN} 位，默认 {self.DEFAULT_PASSWORD}）。\n"
            "重置后该账号的登录态立即失效，需用新密码重新登录；原密码无需提供。")
        tip.setWordWrap(True)
        layout.addWidget(tip)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("新密码："))
        self.edt_new_pwd = QLineEdit()
        self.edt_new_pwd.setEchoMode(QLineEdit.Password)
        self.edt_new_pwd.setPlaceholderText("至少 6 位")
        row1.addWidget(self.edt_new_pwd, 1)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("确认密码："))
        self.edt_new_pwd2 = QLineEdit()
        self.edt_new_pwd2.setEchoMode(QLineEdit.Password)
        self.edt_new_pwd2.setPlaceholderText("再次输入新密码")
        row2.addWidget(self.edt_new_pwd2, 1)
        layout.addLayout(row2)

        self.lbl_msg = QLabel("")
        self.lbl_msg.setWordWrap(True)
        self.lbl_msg.setMinimumHeight(20)
        layout.addWidget(self.lbl_msg)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.btn_ok = QPushButton("确定重置")
        self.btn_ok.setDefault(True)
        self.btn_ok.setEnabled(False)          # 校验通过前不可提交
        self.btn_cancel = QPushButton("取消")
        btn_row.addWidget(self.btn_ok)
        btn_row.addWidget(self.btn_cancel)
        layout.addLayout(btn_row)

        self.edt_new_pwd.textChanged.connect(self._validate)
        self.edt_new_pwd2.textChanged.connect(self._validate)
        self.edt_new_pwd2.returnPressed.connect(self._on_accept)
        self.btn_ok.clicked.connect(self._on_accept)
        self.btn_cancel.clicked.connect(self.reject)

        # 默认填入 123456（含确认框），管理员可直接点「确定重置」；也可改填自定义密码
        self.edt_new_pwd.setText(self.DEFAULT_PASSWORD)
        self.edt_new_pwd2.setText(self.DEFAULT_PASSWORD)
        self._validate()
        self.edt_new_pwd.selectAll()

    def _validate(self, *_):
        new = self.edt_new_pwd.text()
        confirm = self.edt_new_pwd2.text()
        self.btn_ok.setEnabled(self._check(new, confirm))

    def _check(self, new, confirm) -> bool:
        if not new and not confirm:
            self.lbl_msg.clear()
            return False
        if len(new) < self.MIN_LEN:
            self.lbl_msg.setText(f"⚠ 新密码至少 {self.MIN_LEN} 位，当前 {len(new)} 位")
            self.lbl_msg.setStyleSheet(f"color:{RED};")
            return False
        if new != confirm:
            self.lbl_msg.setText("⚠ 两次输入的新密码不一致")
            self.lbl_msg.setStyleSheet(f"color:{RED};")
            return False
        self.lbl_msg.setText("✅ 校验通过，可提交重置")
        self.lbl_msg.setStyleSheet(f"color:{GREEN};")
        return True

    def _on_accept(self):
        new = self.edt_new_pwd.text()
        if not self._check(new, self.edt_new_pwd2.text()):
            self.edt_new_pwd.setFocus()
            return
        self.accept()

    def new_password(self) -> str:
        return self.edt_new_pwd.text()


class MainWindow(QMainWindow):
    def __init__(self, svc=None):
        super().__init__()
        # 界面由 gui.ui 定义，加载后所有具名控件成为本实例的属性
        uic.loadUi(UI_PATH, self)

        # 允许自由拉伸：最小尺寸放得很小，日志区可拖动分隔条调整
        self.setMinimumSize(420, 320)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([590, 160])

        # ---- 业务对象 ----
        # 登录成功后复用登录框所持的服务实例，登录态（current_user）才能延续到存证操作；
        # 未传 svc 时（如单独实例化本窗口）按默认配置自建。
        if svc is None:
            chain = EvidenceChain(nodes=["node-A", "node-B", "node-C"],
                                  required_confirmations=2)
            svc = FileEvidenceService(chain, state_path=config.STATE_PATH)
        self.svc = svc
        self.chain = svc.chain
        self._keystore = KeyStore()
        self._account_signer = None           # 登录后从本地 KeyStore 加载/生成的账号密钥
        self.uploader = None                  # 存证签署使用的签名者（= self._account_signer，登录后填充）
        self.auditor = cc.Signer.generate()    # 审计方身份（演示用，可保持随机生成）
        self._file_counter = 0
        self._apply_theme()                     # 统一深色科技主题 QSS
        self._signed_file = None               # 最近一次签署的 (name, data)
        self._last_file_id = None
        self.tab1_file = None                  # (name, data) → (name, data, digest)
        self.tab2_file = None                  # (name, data)
        self._last_recovered = None            # 最近一次成功解密的 (filename, plaintext_bytes)
        self._workers = []

        # 三重校验结果行：名称 → .ui 中的 QLabel
        self.rows = {
            "链上存证": self.row_chain,
            "完整性(SM3)": self.row_digest,
            "签名(SM2)": self.row_sign,
        }

        # 审计方验证行：动态插入到「签名(SM2)」之后、结论之前；默认隐藏，仅有审计方签认时才显示
        self.row_auditor = QLabel("")
        self.row_auditor.setWordWrap(True)
        self.row_auditor.setVisible(False)
        result_layout = self.result_box.layout()
        result_layout.insertWidget(
            result_layout.indexOf(self.lbl_conclusion), self.row_auditor)
        self.rows["审计方签名"] = self.row_auditor

        # 页面改为「导航按钮 + 整页覆盖」：隐藏 QTabWidget 的标签栏，仅保留内容区
        self.tabs.tabBar().setVisible(False)
        self.tabs.setDocumentMode(True)
        self._nav_buttons = [self.btn_nav_sign, self.btn_nav_verify,
                             self.btn_nav_search, self.btn_nav_decrypt,
                             self.btn_nav_report, self.btn_nav_center,
                             self.btn_nav_logs, self.btn_nav_users]
        self._admin_ready = False

        self.resize(1200, 760)                 # 大厂风格默认窗口尺寸
        self._restructure_layout()             # 三区骨架：顶栏 / 左导航 / 主内容 / 状态栏

        self._augment_ui()                     # 代码动态创建新增控件（检索 / 解密 / 导出）
        self._mount_ai_page()                  # 新增「AI 语义」导航项与页面（须在 _bind 前）
        self._bind()                           # 先有控件再绑信号
        self._reset_rows()
        self._load_history()                   # 重启后从本地快照回填历史链上存证
        self._apply_session()                  # 登录态、用户中心、权限页可见性
        self._refresh_log_view()               # 从数据库加载历史日志填充独立日志页

        self.log("系统就绪：模拟联盟链节点 node-A / node-B / node-C，共识确认数 2", module="system")
        self.log(f"审计方身份已生成，公钥指纹 {self.auditor.pubkey_fingerprint}", module="system")
        self.log("登录后将为您加载/生成专属 SM2 密钥对（本地加密存储，私钥永不入库）", module="auth")
        self.log("提示：把任意文件拖入虚线框（或点击选择），自动计算 SM3 指纹", module="system")

    # ------------------------------------------------------------- 信号绑定
    def _bind(self):
        self.drop_sign.fileLoaded.connect(self.on_sign_file)
        self.drop_verify.fileLoaded.connect(self.on_verify_file)
        self.btn_sign.clicked.connect(self.on_sign)
        self.btn_countersign.clicked.connect(self.on_countersign)
        self.btn_verify.clicked.connect(self.on_verify)
        self.btn_tamper.clicked.connect(self.on_tamper)
        self.btn_forge.clicked.connect(self.on_forge)

        # 独立日志页
        self.btn_logs_refresh.clicked.connect(self._refresh_log_view)
        self.btn_logs_clear.clicked.connect(self._clear_logs)
        self.cmb_log_module.currentIndexChanged.connect(self._refresh_log_view)

        # 页面导航：点击按钮整页切换
        for idx, btn in enumerate(self._nav_buttons):
            btn.clicked.connect(lambda _=False, i=idx: self._goto_page(i))
        self.btn_logout.clicked.connect(self._logout)

        # 用户中心
        self.btn_change_pwd.clicked.connect(self._change_password)

        # 用户权限管理（仅超级管理员可访问该页）
        self.btn_refresh_users.clicked.connect(self._refresh_users)
        self.btn_make_admin.clicked.connect(lambda: self._change_user_role("admin"))
        self.btn_make_user.clicked.connect(lambda: self._change_user_role("user"))
        self.btn_enable_user.clicked.connect(lambda: self._change_user_status("enabled"))
        self.btn_disable_user.clicked.connect(lambda: self._change_user_status("disabled"))
        self.btn_reset_user_pwd.clicked.connect(self._reset_user_password)
        self.btn_delete_user.clicked.connect(self._delete_user)

        # 代码动态创建的新增控件信号
        self.btn_search.clicked.connect(self.on_search)
        self.edt_search.returnPressed.connect(self.on_search)
        self.tbl_search_results.doubleClicked.connect(self._on_search_double_clicked)
        self.btn_decrypt_verify.clicked.connect(self.on_decrypt_and_verify)
        self.edt_decrypt_passphrase.returnPressed.connect(self.on_decrypt_and_verify)
        self.btn_pick_current.clicked.connect(self._pick_file_id_from_current)
        self.btn_export_report.clicked.connect(self.on_export_report)
        self.btn_save_recovered.clicked.connect(self.on_save_recovered)

        for lbl in (self.lbl_sign_digest, self.lbl_verify_digest, self.lbl_sign_result):
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)

        if self.uploader is not None:
            self.lbl_uploader_id.setText(f"上传方公钥指纹：{self.uploader.pubkey_fingerprint}")
        else:
            self.lbl_uploader_id.setText("上传方公钥指纹：待登录后加载账号密钥")
        self.lbl_auditor_id.setText(f"审计方公钥指纹：{self.auditor.pubkey_fingerprint}")

    # ------------------------------------------------------- 主窗口背景绘制
    def paintEvent(self, event):
        """主窗口背景：加载 assets/main_bg.png 全窗口拉伸铺底 + 渐变遮罩压暗，
        保证表格与文字可读；缺失时回退深色渐变（与登录页配色一致）。"""
        painter = QPainter(self)
        bg_path = os.path.join(config.BASE_DIR, "app", "assets", "main_bg.png")
        pixmap = QPixmap(bg_path)
        if pixmap.isNull():
            # 回退：深蓝科技渐变
            grad = QLinearGradient(0, 0, self.width(), self.height())
            grad.setColorAt(0, QColor("#050D1F"))
            grad.setColorAt(1, QColor("#0A1E42"))
            painter.fillRect(self.rect(), grad)
        else:
            # 拉伸铺底
            painter.drawPixmap(self.rect(), pixmap)
            # 右侧/底部渐变遮罩压暗，提升文字可读性
            overlay = QLinearGradient(0, 0, self.width(), self.height())
            overlay.setColorAt(0, QColor(5, 13, 31, 120))
            overlay.setColorAt(0.5, QColor(5, 13, 31, 160))
            overlay.setColorAt(1, QColor(5, 13, 31, 210))
            painter.fillRect(self.rect(), overlay)
        painter.end()

    # ------------------------------------------------ 三区骨架重构（顶栏 / 左导航 / 状态栏）
    def _restructure_layout(self):
        """把 gui.ui 的「横排导航 + 上下分栏」三区骨架：
        顶栏（产品名 / 用户 / 退出） + 左侧导航竖栏 + 主内容 + 底部状态栏。
        保留 gui.ui 中各业务页内容不动，仅重组顶层容器。
        """
        root = self.centralwidget.layout()
        nav_bar = self.nav_bar
        nav_layout = nav_bar.layout()

        # ---------- 顶栏 ----------
        self.top_bar = QFrame()
        self.top_bar.setObjectName("top_bar")
        self.top_bar.setFixedHeight(52)
        top_layout = QHBoxLayout(self.top_bar)
        top_layout.setContentsMargins(20, 0, 20, 0)
        top_layout.setSpacing(12)
        brand = QLabel("信链")
        brand.setObjectName("lbl_brand")
        brand_sub = QLabel("国密区块链电子文件存证平台")
        brand_sub.setObjectName("lbl_brand_sub")
        top_layout.addWidget(brand)
        top_layout.addWidget(brand_sub)
        top_layout.addStretch()

        # 当前用户标签移入顶栏
        nav_layout.removeWidget(self.lbl_nav_user)
        self.lbl_nav_user.setParent(self.top_bar)
        top_layout.addWidget(self.lbl_nav_user)

        self.btn_logout = QPushButton("退出登录")
        self.btn_logout.setObjectName("btn_logout")
        top_layout.addWidget(self.btn_logout)

        # ---------- 左侧导航竖栏 ----------
        self.side_nav = QFrame()
        self.side_nav.setObjectName("side_nav")
        self.side_nav.setFixedWidth(196)
        side_layout = QVBoxLayout(self.side_nav)
        side_layout.setContentsMargins(12, 16, 12, 16)
        side_layout.setSpacing(6)
        nav_icons = {
            "btn_nav_sign": "✎", "btn_nav_verify": "✓", "btn_nav_search": "⌕",
            "btn_nav_decrypt": "🔓", "btn_nav_report": "▤", "btn_nav_center": "◉",
            "btn_nav_logs": "☰", "btn_nav_users": "⚙",
        }
        for btn in self._nav_buttons:
            nav_layout.removeWidget(btn)
            btn.setParent(self.side_nav)
            btn.setMinimumHeight(40)
            btn.setAutoExclusive(True)
            icon = nav_icons.get(btn.objectName())
            if icon and not btn.text().startswith(icon):
                btn.setText(f"{icon}  {btn.text()}")
            side_layout.addWidget(btn)
        side_layout.addStretch()

        # 移除旧横排导航条
        root.removeWidget(nav_bar)
        nav_bar.setParent(None)
        nav_bar.deleteLater()

        # ---------- 主内容区（右侧 tabs） ----------
        splitter = self.splitter
        self.tabs.setParent(None)
        self.body = QWidget()
        self.body.setObjectName("body")
        body_layout = QHBoxLayout(self.body)
        body_layout.setContentsMargins(16, 16, 16, 12)
        body_layout.setSpacing(12)
        body_layout.addWidget(self.side_nav)
        body_layout.addWidget(self.tabs, 1)
        splitter.setParent(None)
        splitter.deleteLater()

        # ---------- 底部状态栏 ----------
        self.status_bar = QFrame()
        self.status_bar.setObjectName("status_bar")
        self.status_bar.setFixedHeight(30)
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(20, 0, 20, 0)
        self.lbl_status = QLabel("节点 node-A / node-B / node-C · 链高度 — · 已连接")
        self.lbl_status.setObjectName("lbl_status")
        self.lbl_status_version = QLabel("版本 v2.0")
        self.lbl_status_version.setObjectName("lbl_status_version")
        status_layout.addWidget(self.lbl_status)
        status_layout.addStretch()
        status_layout.addWidget(self.lbl_status_version)

        # ---------- 组装三区 ----------
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self.top_bar)
        root.addWidget(self.body, 1)
        root.addWidget(self.status_bar)

        # 业务页统一内边距 ≥16，形成卡片化留白
        for name in ("tab_sign", "tab_verify", "tab_search", "tab_decrypt",
                     "tab_report", "tab_center", "tab_logs", "tab_users"):
            page = getattr(self, name, None)
            if page is not None and page.layout() is not None:
                page.layout().setContentsMargins(20, 20, 20, 20)
                page.layout().setSpacing(12)

    def _update_status_bar(self):
        """刷新底部状态栏：节点 / 链高度 / 连接状态 / 当前用户。"""
        if not hasattr(self, "lbl_status"):
            return
        nodes = " / ".join(self.chain.nodes)
        user = self.svc.current_user()
        if user:
            role = ROLE_NAMES.get(user["role"], user["role"])
            who = f"{user['display_name']}（{role}）"
        else:
            who = "未登录"
        self.lbl_status.setText(
            f"节点 {nodes} · 链高度 {self.chain.height()} · 已连接 · 当前用户 {who}")

    # ------------------------------------------------------- 统一深色科技主题
    def _apply_theme(self):
        """加载 app/theme.qss 统一深色主题；缺失时回退内置样式。"""
        qss_path = os.path.join(config.BASE_DIR, "app", "theme.qss")
        try:
            with open(qss_path, "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        except OSError:
            self.setStyleSheet(
                "QWidget { color:#E6F1FF; font-size:13px; }"
                "QGroupBox { border:1px solid #35A7FF; border-radius:10px; "
                "background:rgba(10,30,66,160); margin-top:12px; padding:14px; }"
                "QTableWidget { background:rgba(5,13,31,180); border:1px solid #2E5BBA; }"
            )

    # ------------------------------------------------------- 动态扩充 GUI 控件
    def _augment_ui(self):
        """在 gui.ui 已新增的 tab_search / tab_decrypt 页面上，代码填充检索 / 解密 / 导出控件。"""

        # --- 1) 存证检索页 ---
        search_layout = self.tab_search.layout()
        lbl_search_hint = QLabel(
            "进入本页默认展示您可查看的全部存证（管理员 / 超级管理员=全部、普通用户=本人上传、未登录=匿名存证）；"
            "输入 file_id / 文件名关键词 / SM3 指纹片段即在可查看范围内过滤，越权存证不会出现。"
            "双击一行可跳转到「授权解密」页并自动填入 file_id。")
        lbl_search_hint.setWordWrap(True)
        lbl_search_hint.setStyleSheet(f"color:{GRAY};")
        search_layout.addWidget(lbl_search_hint)

        search_group = QGroupBox("存证检索（空检索词=可查看列表；关键词=在可查看范围内过滤）")
        search_group.setStyleSheet(
            "QGroupBox { font-weight:bold; border:1px solid #3E7BFA; border-radius:6px; margin-top:10px; } "
            "QGroupBox::title { subcontrol-origin: margin; left:10px; padding:0 4px; }")
        v1 = QVBoxLayout()
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("检索词："))
        self.edt_search = QLineEdit()
        self.edt_search.setPlaceholderText("输入 file_id / 文件名关键词 / SM3 指纹片段；留空则列出全部可查看存证")
        h1.addWidget(self.edt_search, 1)
        self.btn_search = QPushButton("🔍 检索")
        h1.addWidget(self.btn_search)
        v1.addLayout(h1)
        self.lbl_search_summary = QLabel("当前显示可查看的 0 条存证")
        self.lbl_search_summary.setStyleSheet(f"color:{GRAY}; font-weight:bold;")
        v1.addWidget(self.lbl_search_summary)
        self.tbl_search_results = QTableWidget(0, 6)
        self.tbl_search_results.setHorizontalHeaderLabels(
            ["file_id", "存证号", "文件名", "上传账号", "指纹(SM3)", "匹配方式"])
        self.tbl_search_results.horizontalHeader().setStretchLastSection(True)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.tbl_search_results.verticalHeader().setVisible(False)
        self.tbl_search_results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_search_results.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_search_results.setToolTip("双击一行自动跳转到「授权解密」页并填入 file_id")
        v1.addWidget(self.tbl_search_results)
        search_group.setLayout(v1)
        search_layout.addWidget(search_group, 1)

        # --- 2) 授权解密与报告页 ---
        decrypt_layout = self.tab_decrypt.layout()
        lbl_decrypt_hint = QLabel(
            "输入 file_id 与存证时设置的授权口令，解密还原后自动与链上 SM3 比对完成验真闭环；"
            "「导出证据报告」以当前验真页选中的链上存证为准。")
        lbl_decrypt_hint.setWordWrap(True)
        lbl_decrypt_hint.setStyleSheet(f"color:{GRAY};")
        decrypt_layout.addWidget(lbl_decrypt_hint)

        decrypt_group = QGroupBox("授权解密还原（需存证口令 · PBKDF2 高强度 KDF）")
        decrypt_group.setStyleSheet(
            "QGroupBox { font-weight:bold; border:1px solid #21C8F6; border-radius:6px; margin-top:10px; } "
            "QGroupBox::title { subcontrol-origin: margin; left:10px; padding:0 4px; }")
        v2 = QVBoxLayout()
        h2 = QHBoxLayout()
        self.btn_pick_current = QPushButton("📌 取验真页选中存证")
        h2.addWidget(self.btn_pick_current)
        h2.addWidget(QLabel("file_id："))
        self.edt_decrypt_file_id = QLineEdit()
        self.edt_decrypt_file_id.setPlaceholderText("例：FILE-001")
        self.edt_decrypt_file_id.setFixedWidth(140)
        h2.addWidget(self.edt_decrypt_file_id)
        h2.addWidget(QLabel("口令："))
        self.edt_decrypt_passphrase = QLineEdit()
        self.edt_decrypt_passphrase.setEchoMode(QLineEdit.Password)
        self.edt_decrypt_passphrase.setPlaceholderText("加密时设置的口令（PBKDF2 20万次迭代）")
        h2.addWidget(self.edt_decrypt_passphrase, 1)
        self.btn_decrypt_verify = QPushButton("🔓 解密并验真（闭环）")
        self.btn_decrypt_verify.setStyleSheet("background:#21C8F6; color:#02121f; font-weight:bold; padding:6px 14px;")
        h2.addWidget(self.btn_decrypt_verify)
        v2.addLayout(h2)
        self.lbl_decrypt_result = QLabel("— 输入 file_id + 口令后点击按钮 —")
        self.lbl_decrypt_result.setWordWrap(True)
        self.lbl_decrypt_result.setStyleSheet(f"color:{GRAY}; padding:6px;")
        self.lbl_decrypt_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v2.addWidget(self.lbl_decrypt_result)
        decrypt_group.setLayout(v2)
        decrypt_layout.addWidget(decrypt_group, 1)

        # --- 3) 保存还原明文（解密成功后可用，引导到验真页做指纹比对） ---
        self.btn_save_recovered = QPushButton("💾 保存还原明文到本地（供验真）")
        self.btn_save_recovered.setStyleSheet(
            "QPushButton { background:#1DC981; color:#02121f; padding:8px 16px; border-radius:4px; font-weight:bold; } "
            "QPushButton:hover { background:#21C8F6; } "
            "QPushButton:disabled { background:#444; color:#888; }")
        self.btn_save_recovered.setEnabled(False)
        decrypt_layout.addWidget(self.btn_save_recovered)

        # --- 4) 导出证据报告（独立一行） ---
        self.btn_export_report = QPushButton("📄 导出证据报告 (DOCX/PDF)")
        self.btn_export_report.setStyleSheet(
            "QPushButton { background:#3E7BFA; color:#ffffff; padding:8px 16px; border-radius:4px; } "
            "QPushButton:hover { background:#21C8F6; }")
        decrypt_layout.addWidget(self.btn_export_report)

        # --- 5) 用户中心：存证统计卡片（按角色展示可查看范围的统计） ---
        self._build_center_stats()

        # --- 6) 独立「操作日志」页（业务页不再内嵌日志栏） ---
        self._build_log_page()

        # --- 7) 报告页 UI ---
        self._build_report_tab()

        # --- 8) 表格统一斑马纹 / 行高 / 排序 ---
        for table in (self.tbl_search_results, self.tbl_users,
                      self.tbl_logs, self.tbl_report_evidence):
            table.setAlternatingRowColors(True)
            table.verticalHeader().setDefaultSectionSize(36)
            table.setSortingEnabled(True)
        self.tbl_search_results.setSortingEnabled(False)   # 检索结果按权限顺序展示

    def _build_center_stats(self):
        """把用户中心页重构为「身份卡 + 2×2 统计卡网格 + 修改密码卡」的卡片化布局。

        - 身份卡：在账号信息组左侧追加圆形头像占位 + 右侧角色徽标。
        - 统计卡：2×2 网格，前三张为真实数据（本人存证数 / 可查看存证数 / 最近存证时间），
          第四张按角色显示「系统用户数」（admin 及以上）或「开发中」占位卡（普通用户）。
        - 修改密码卡：沿用 .ui 中的 pwd_group。
        """
        # ---------- 1) 身份卡：为账号信息组追加头像占位与角色徽标 ----------
        self.profile_group.setTitle("身份信息")
        profile_grid = self.profile_group.layout()
        # 圆形头像占位（取用户名首字，深色渐变底）
        self.lbl_center_avatar = QLabel("●")
        self.lbl_center_avatar.setAlignment(Qt.AlignCenter)
        self.lbl_center_avatar.setFixedSize(76, 76)
        self.lbl_center_avatar.setStyleSheet(
            "QLabel { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3E7BFA,stop:1 #21C8F6);"
            " color:#FFFFFF; border:2px solid rgba(53,167,255,120);"
            " border-radius:38px; font-size:30px; font-weight:bold; }")
        self.lbl_center_avatar.setToolTip("账号头像（占位）")
        profile_grid.addWidget(self.lbl_center_avatar, 0, 2, 5, 1, Qt.AlignTop | Qt.AlignHCenter)

        # 角色徽标（与角色同一行右侧）
        self.lbl_center_role_badge = QLabel("")
        self.lbl_center_role_badge.setAlignment(Qt.AlignCenter)
        self.lbl_center_role_badge.setFixedHeight(22)
        self.lbl_center_role_badge.setStyleSheet(
            "QLabel { background:#1DC981; color:#02121f; border-radius:11px; padding:0 12px; font-weight:bold; }")
        profile_grid.addWidget(self.lbl_center_role_badge, 2, 1, Qt.AlignLeft)

        # 账号字段值统一高对比：纯白 / 显示名称加粗放大 / 注册时间弱化
        self.lbl_center_username.setStyleSheet("color:#FFFFFF; font-size:14px;")
        self.lbl_center_display.setStyleSheet("color:#FFFFFF; font-size:16px; font-weight:bold;")
        self.lbl_center_created.setStyleSheet("color:#C7D9EE; font-size:13px;")
        self.lbl_center_status.setStyleSheet("color:#1DC981; font-size:14px; font-weight:bold;")

        # ---------- 2) 统计卡 2×2 网格 ----------
        stats_group = QGroupBox("数据概览")
        stats_group.setStyleSheet(
            "QGroupBox { font-weight:bold; border:1px solid rgba(53,167,255,110); border-radius:10px;"
            " margin-top:12px; padding:14px; background:rgba(10,30,66,160); } "
            "QGroupBox::title { subcontrol-origin: margin; left:14px; padding:0 6px;"
            " color:#21C8F6; font-size:13px; }")
        grid = QGridLayout()
        grid.setSpacing(12)

        # 统一卡片样式：深色半透明底 + 左上标题 + 大字号数值
        card_qss = (
            "QFrame { background:rgba(13,43,94,200); border:1px solid rgba(53,167,255,110);"
            " border-radius:10px; }"
        )

        def make_card(title, value_color="#21C8F6", placeholder=False):
            card = QFrame()
            card.setStyleSheet(card_qss)
            card.setMinimumHeight(96)
            lay = QVBoxLayout(card)
            lay.setContentsMargins(16, 12, 16, 12)
            lbl_title = QLabel(title)
            lbl_title.setStyleSheet("color:#9CC3E8; font-size:12px;")
            lbl_value = QLabel("—")
            lbl_value.setStyleSheet(
                f"font-weight:bold; font-size:24px; color:{'#7C8DA6' if placeholder else value_color};")
            lay.addWidget(lbl_title)
            lay.addWidget(lbl_value)
            if placeholder:
                tag = QLabel("开发中")
                tag.setAlignment(Qt.AlignRight)
                tag.setStyleSheet("color:#7C8DA6; font-size:11px;")
                lay.addWidget(tag)
            return card, lbl_value

        # 第 1 张：本人存证数
        self._card_mine, self.lbl_stats_mine = make_card("本人存证数", "#21C8F6")
        # 第 2 张：可查看存证数
        self._card_evidence, self.lbl_stats_evidence = make_card("可查看存证数", "#1DC981")
        # 第 3 张：最近存证时间
        self._card_recent, self.lbl_stats_recent = make_card("最近存证时间", "#F0B429")
        # 第 4 张：系统用户数（admin+）/ 开发中占位（普通用户）
        self._card_users, self.lbl_stats_users = make_card("系统用户数", "#1DC981")
        self._card_placeholder, self.lbl_stats_placeholder = make_card(
            "我的授权记录", placeholder=True)

        grid.addWidget(self._card_mine, 0, 0)
        grid.addWidget(self._card_evidence, 0, 1)
        grid.addWidget(self._card_recent, 1, 0)
        # 第 4 张由 _refresh_center_stats 按角色切换显示
        grid.addWidget(self._card_users, 1, 1)
        grid.addWidget(self._card_placeholder, 1, 1)
        self._card_placeholder.setVisible(False)

        stats_group.setLayout(grid)
        # 插入到账号信息（index 0）之后、修改密码之前
        self.center_body_layout.insertWidget(1, stats_group)

        # 范围说明（保留原标签语义，挂在统计组下方）
        self.lbl_stats_scope = QLabel("统计范围：—")
        self.lbl_stats_scope.setStyleSheet("color:#9CC3E8; font-size:12px;")
        self.center_body_layout.insertWidget(2, self.lbl_stats_scope)

        # 修改密码改为独立弹窗入口：隐藏 .ui 内嵌的输入区，只保留一个入口卡片
        self._build_password_entry_card()

    def _build_password_entry_card(self):
        """把内嵌修改密码输入区替换为「账号安全」入口卡（改密走独立深色弹窗）。"""
        self.pwd_group.setVisible(False)      # 隐藏常驻的原密码/新密码输入框
        self.lbl_pwd_hint.setVisible(False)

        card = QGroupBox("账号安全")
        card.setStyleSheet(
            "QGroupBox { font-weight:bold; border:1px solid rgba(53,167,255,110); border-radius:10px;"
            " margin-top:12px; padding:14px; background:rgba(10,30,66,160); } "
            "QGroupBox::title { subcontrol-origin: margin; left:14px; padding:0 6px;"
            " color:#21C8F6; font-size:13px; }")
        row = QHBoxLayout(card)
        row.setContentsMargins(14, 14, 14, 14)
        tip = QLabel("修改登录密码将通过独立弹窗完成；修改后当前会话保持有效，下次登录请使用新密码。")
        tip.setWordWrap(True)
        tip.setStyleSheet("color:#9CC3E8; font-size:12px;")
        self.btn_open_change_pwd = QPushButton("修改密码")
        self.btn_open_change_pwd.setMinimumSize(0, 32)
        self.btn_open_change_pwd.setStyleSheet(
            "QPushButton { background:#1DC981; color:#02121f; font-weight:bold; padding:6px 20px; "
            "border-radius:4px; } QPushButton:hover { background:#21C8F6; }")
        self.btn_open_change_pwd.clicked.connect(self._change_password)
        row.addWidget(tip, 1)
        row.addWidget(self.btn_open_change_pwd)

        # 插到「修改密码」原位置之前（即统计范围说明之后），保证顺序：身份 → 统计 → 账号安全
        idx = self.center_body_layout.indexOf(self.pwd_group)
        self.center_body_layout.insertWidget(idx if idx >= 0 else 3, card)

    def _refresh_center_stats(self):
        """按当前登录角色刷新中心页统计数据。"""
        user = self.svc.current_user()
        if not user:
            return
        is_privileged = user["role"] in ("admin", "superadmin")

        # 头像首字
        name = (user["display_name"] or user["username"] or "?").strip()
        self.lbl_center_avatar.setText(name[0].upper())

        # 角色徽标
        role = user["role"]
        badge_color = {"superadmin": "#E8463A", "admin": "#3E7BFA", "user": "#1DC981"}.get(role, "#1DC981")
        self.lbl_center_role_badge.setText(ROLE_NAMES.get(role, role))
        self.lbl_center_role_badge.setStyleSheet(
            f"QLabel {{ background:{badge_color}; color:#fff; border-radius:11px; padding:0 12px; font-weight:bold; }}")

        # 账号状态：启用绿 / 禁用红
        status = user.get("status")
        self.lbl_center_status.setStyleSheet(
            f"color:{GREEN if status == 'enabled' else RED}; font-size:14px; font-weight:bold;")

        # 本人存证数：登录用户本人上传
        try:
            mine = self.svc.count_evidence(actor=user["username"])
        except Exception:
            mine = 0
        self.lbl_stats_mine.setText(str(mine))

        # 可查看存证数：按角色范围
        try:
            ev_count = self.svc.count_evidence()
        except Exception:
            ev_count = 0
        self.lbl_stats_evidence.setText(str(ev_count))

        # 最近存证时间：取当前用户可查看列表中最新一条
        recent_ts = self._latest_evidence_ts()
        self.lbl_stats_recent.setText(recent_ts)

        # 第四张卡：admin+ 显示系统用户数，普通用户显示开发中占位
        if is_privileged:
            self._card_users.setVisible(True)
            self._card_placeholder.setVisible(False)
            try:
                user_count = len(self.svc.list_users())
            except Exception:
                user_count = 0
            self.lbl_stats_users.setText(str(user_count))
            self.lbl_stats_scope.setText("统计范围：系统全部存证")
        else:
            self._card_users.setVisible(False)
            self._card_placeholder.setVisible(True)
            self.lbl_stats_scope.setText("统计范围：本人上传的存证")

    def _latest_evidence_ts(self) -> str:
        """取当前登录用户可查看存证中最新一条的时间；无则返回「暂无」。"""
        try:
            records = self.svc.list_evidence()
        except Exception:
            return "暂无"
        ts_list = [r.get("created_at") for r in records if r.get("created_at")]
        if not ts_list:
            return "暂无"
        latest = max(ts_list)
        # created_at 为 ISO 格式字符串，截取到日期
        return (latest or "").replace("T", " ")[:10] or "暂无"

    def _build_log_page(self):
        """构建独立「操作日志」页：模块筛选 + 刷新/清空 + 表格（按用户隔离）。"""
        layout = self.tab_logs.layout()

        hint = QLabel(
            "日志按账号隔离：普通用户仅见本人操作日志；管理员可见本人操作日志 + 系统日志；"
            "超级管理员可见全部日志。清空按钮中，超级管理员可清空全部，其余角色仅清空本人操作日志。")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{GRAY};")
        layout.addWidget(hint)

        filter_group = QGroupBox("日志筛选")
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("模块："))
        self.cmb_log_module = QComboBox()
        self.cmb_log_module.addItem("全部", None)
        for mod in self.LOG_MODULES:
            self.cmb_log_module.addItem(self.LOG_MODULE_LABELS.get(mod, mod), mod)
        filter_row.addWidget(self.cmb_log_module)
        self.btn_logs_refresh = QPushButton("🔄 刷新")
        self.btn_logs_clear = QPushButton("🗑 清空可见日志")
        filter_row.addWidget(self.btn_logs_refresh)
        filter_row.addWidget(self.btn_logs_clear)
        filter_row.addStretch()
        filter_group.setLayout(filter_row)
        layout.addWidget(filter_group)

        self.tbl_logs = QTableWidget(0, 4)
        self.tbl_logs.setHorizontalHeaderLabels(["时间", "模块", "操作人", "内容"])
        self.tbl_logs.setAlternatingRowColors(True)
        self.tbl_logs.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_logs.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_logs.verticalHeader().setVisible(False)
        self.tbl_logs.setWordWrap(True)
        self.tbl_logs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_logs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_logs.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl_logs.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.tbl_logs, 1)

        self.lbl_logs_msg = QLabel("—")
        self.lbl_logs_msg.setStyleSheet(f"color:{GRAY};")
        self.lbl_logs_msg.setWordWrap(True)
        layout.addWidget(self.lbl_logs_msg)

    # --------------------------------------------------- AI 语义（前端可见）
    def _mount_ai_page(self):
        """插入「AI 语义」导航项与页面：状态、已建索引、试检索三块，均可现场验证。"""
        page = QWidget()
        page.setObjectName("tab_ai")
        self.tab_ai = page
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(10)

        # ① 引擎状态
        status_group = QGroupBox("① AI 引擎状态")
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(6)
        self.lbl_ai_rows = {}
        items = [
            ("llm", "对话模型（摘要/分类）"),
            ("api", "接口地址"),
            ("key", "API Key"),
            ("content", "正文节选上限"),
            ("emb", "向量模型（召回）"),
            ("vec", "向量库条目"),
        ]
        for i, (key, label) in enumerate(items):
            name = QLabel(label)
            name.setStyleSheet(f"color:{GRAY};")
            value = QLabel("—")
            value.setWordWrap(True)
            grid.addWidget(name, i, 0)
            grid.addWidget(value, i, 1)
            self.lbl_ai_rows[key] = value
        grid.setColumnStretch(1, 1)
        top_row = QHBoxLayout()
        self.btn_ai_refresh = QPushButton("🔄 刷新状态")
        self.btn_ai_refresh.setStyleSheet(
            "QPushButton { background:#2E5BBA; color:#fff; padding:6px 14px; border-radius:4px; }")
        top_row.addLayout(grid, 1)
        top_row.addWidget(self.btn_ai_refresh, 0, Qt.AlignTop)
        status_group.setLayout(top_row)
        layout.addWidget(status_group)

        # ② 已建立的语义索引
        index_group = QGroupBox("② 已建立的 AI 语义索引（加密前本地生成，不含原文）")
        index_layout = QVBoxLayout()
        self.lbl_ai_index_summary = QLabel("正在加载…")
        self.lbl_ai_index_summary.setStyleSheet(f"color:{GRAY};")
        index_layout.addWidget(self.lbl_ai_index_summary)
        self.tbl_ai_index = QTableWidget(0, 4)
        self.tbl_ai_index.setHorizontalHeaderLabels(["文件名", "分类", "AI 语义摘要", "AI 关键词"])
        self.tbl_ai_index.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_ai_index.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_ai_index.verticalHeader().setVisible(False)
        self.tbl_ai_index.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_ai_index.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_ai_index.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_ai_index.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        index_layout.addWidget(self.tbl_ai_index, 1)
        index_group.setLayout(index_layout)
        layout.addWidget(index_group, 1)

        # ③ 语义检索试验
        probe_group = QGroupBox("③ 语义检索试验（字面不重合也能召回）")
        probe_layout = QVBoxLayout()
        row = QHBoxLayout()
        self.edt_ai_query = QLineEdit()
        self.edt_ai_query.setPlaceholderText("例如：逾期履行要赔多少钱？")
        self.btn_ai_probe = QPushButton("试检索")
        self.btn_ai_probe.setStyleSheet(
            "QPushButton { background:#1DC981; color:#fff; padding:6px 16px; border-radius:4px; }")
        row.addWidget(self.edt_ai_query, 1)
        row.addWidget(self.btn_ai_probe)
        probe_layout.addLayout(row)
        self.txt_ai_probe = QPlainTextEdit()
        self.txt_ai_probe.setReadOnly(True)
        self.txt_ai_probe.setMaximumBlockCount(200)
        self.txt_ai_probe.setPlaceholderText("检索结果会显示 query 向量维度、top-3 相似度与命中文件")
        probe_layout.addWidget(self.txt_ai_probe, 1)
        probe_group.setLayout(probe_layout)
        layout.addWidget(probe_group, 1)

        # 插入 tabs 与导航
        anchor = self.tabs.indexOf(self.tab_search)
        at = (anchor + 1) if anchor >= 0 else self.tabs.count()
        self.tabs.insertTab(at, page, "AI 语义")

        btn = QPushButton("✦  AI 语义")
        btn.setObjectName("btn_nav_ai")
        btn.setMinimumHeight(40)
        btn.setAutoExclusive(True)
        side_layout = self.side_nav.layout()
        side_layout.insertWidget(side_layout.indexOf(self.btn_nav_search) + 1, btn)
        self._nav_buttons.insert(at, btn)

        # 导航信号由 _bind 统一按索引绑定，这里不再单独连接
        self.btn_ai_refresh.clicked.connect(self._refresh_ai_page)
        self.btn_ai_probe.clicked.connect(self._ai_probe)
        self.edt_ai_query.returnPressed.connect(self._ai_probe)

        # 顶栏状态标识（默认隐藏，仅保留状态刷新逻辑供 AI 语义页使用）
        self.lbl_ai_badge = QLabel("AI 语义：检测中")
        self.lbl_ai_badge.setObjectName("lbl_ai_badge")
        self.top_bar.layout().insertWidget(2, self.lbl_ai_badge)
        self.lbl_ai_badge.setVisible(False)
        self._refresh_ai_page()

    def _refresh_ai_page(self):
        try:
            status = self.svc.semantic_status()
        except Exception as exc:
            self.lbl_ai_rows["llm"].setText(f"读取失败：{exc}")
            return
        llm_on = status["llm_enabled"] and status["key_ready"]
        self.lbl_ai_rows["llm"].setText(
            ("%s（已启用）" % status["llm_model"]) if status["llm_enabled"] else "已关闭")
        self.lbl_ai_rows["api"].setText(status["api_base"] or "（未配置）")
        self.lbl_ai_rows["key"].setText(
            ("已配置（环境变量）" if status["key_ready"] else "未配置 → 语义增强不可用，检索降级为关键词"))
        self.lbl_ai_rows["content"].setText(
            ("最多 %d 字正文节选参与摘要" % status["max_chars"]) if status["reads_content"]
            else "不读取正文（仅用文件名与元数据）")
        self.lbl_ai_rows["emb"].setText(
            ("%s%s" % (status["embedding_model"], "" if status["embedding_ready"] else "（不可用）"))
            if status["embedding_enabled"] else "已关闭")
        self.lbl_ai_rows["vec"].setText("%d 条指纹向量" % status["vector_count"])

        ok_color = "#1DC981" if (llm_on and status["embedding_ready"]) else "#F2A33C"
        self.lbl_ai_badge.setText(
            "● AI 语义已启用 · %s" % status["llm_model"] if (llm_on and status["embedding_ready"])
            else "● AI 语义未就绪 · 降级关键词检索")
        self.lbl_ai_badge.setStyleSheet(
            "QLabel { color:%s; padding:2px 10px; border:1px solid %s; border-radius:10px; }"
            % (ok_color, ok_color))

        items = []
        try:
            items = self.svc.list_semantic_indexes(limit=80)
        except Exception:
            items = []
        self.tbl_ai_index.setRowCount(len(items))
        for row, it in enumerate(items):
            self.tbl_ai_index.setItem(row, 0, QTableWidgetItem(it["file_name"]))
            self.tbl_ai_index.setItem(row, 1, QTableWidgetItem(it["category"] or "—"))
            self.tbl_ai_index.setItem(row, 2, QTableWidgetItem(it["summary"] or "—"))
            self.tbl_ai_index.setItem(row, 3, QTableWidgetItem("、".join(it["keywords"]) or "—"))
        if items:
            self.lbl_ai_index_summary.setText("共 %d 条存证带 AI 语义索引" % len(items))
        else:
            self.lbl_ai_index_summary.setText(
                "暂无 AI 语义索引：完成一次存证签署后，加密前会自动生成摘要与关键词并入库")

    def _ai_probe(self):
        query = self.edt_ai_query.text().strip()
        if not query:
            self.txt_ai_probe.setPlainText("请先输入一句自然语言检索语句。")
            return
        self.txt_ai_probe.setPlainText("检索中…（需调用一次向量接口）")
        QApplication.processEvents()
        try:
            res = self.svc.semantic_probe(query, top_k=3)
        except Exception as exc:
            self.txt_ai_probe.setPlainText(f"检索失败：{type(exc).__name__}: {exc}")
            return
        if not res.get("ok"):
            self.txt_ai_probe.setPlainText("未执行：" + (res.get("reason") or "未知原因"))
            return
        lines = ["query 向量维度：%d" % res["dim"], ""]
        if not res["hits"]:
            lines.append("向量库为空：先完成一次存证签署，才有可比对的向量。")
        for i, hit in enumerate(res["hits"], 1):
            lines.append("%d. 相似度 %.4f  %s" % (i, hit["score"], hit["file_name"]))
            lines.append("   指纹 %s" % short(hit["digest"], 16, 8))
        self.txt_ai_probe.setPlainText("\n".join(lines))
        self.log("🧠 语义试检索：「%s」返回 %d 条候选" % (query, len(res["hits"])), module="search")

    def _build_report_tab(self):
        """构建「存证报告」页：链上存证列表 + 生成报告 + 预览 + 导出。"""
        layout = self.tab_report.layout()
        if layout is None:
            layout = QVBoxLayout(self.tab_report)

        # 顶部：列表区
        list_group = QGroupBox("① 链上存证列表")
        list_layout = QVBoxLayout()
        btn_row = QHBoxLayout()
        self.btn_report_refresh = QPushButton("🔄 刷新列表")
        self.btn_report_refresh.setStyleSheet(
            "QPushButton { background:#2E5BBA; color:#fff; padding:6px 14px; border-radius:4px; }")
        self.cmb_report_kind = QComboBox()
        self.cmb_report_kind.addItem("存证凭证（已上链回执）", "receipt")
        self.cmb_report_kind.addItem("证据报告（三重校验鉴定）", "proof")
        self.cmb_report_kind.setMinimumWidth(210)
        self.chk_report_file = QCheckBox("证据报告附带原文件校验")
        self.chk_report_file.setToolTip("勾选后生成证据报告时选择一份文件，重算 SM3 并与链上比对；"
                                        "不勾选则仅做链上与签名核验，报告会如实标注「未核验」")
        self.btn_report_generate = QPushButton("📄 生成选中存证的报告")
        self.btn_report_generate.setStyleSheet(
            "QPushButton { background:#1DC981; color:#fff; padding:6px 14px; border-radius:4px; }")
        btn_row.addWidget(self.btn_report_refresh)
        btn_row.addWidget(self.cmb_report_kind)
        btn_row.addWidget(self.chk_report_file)
        btn_row.addWidget(self.btn_report_generate)
        btn_row.addStretch()
        list_layout.addLayout(btn_row)

        self.tbl_report_evidence = QTableWidget(0, 4)
        self.tbl_report_evidence.setHorizontalHeaderLabels(["file_id", "存证号", "文件名", "存证时间"])
        self.tbl_report_evidence.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_report_evidence.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_report_evidence.setAlternatingRowColors(True)
        self.tbl_report_evidence.horizontalHeader().setStretchLastSection(True)
        list_layout.addWidget(self.tbl_report_evidence)
        list_group.setLayout(list_layout)
        layout.addWidget(list_group)

        # 中部：报告预览区
        preview_group = QGroupBox("② 报告预览")
        preview_layout = QVBoxLayout()
        self.txt_report_preview = QPlainTextEdit()
        self.txt_report_preview.setReadOnly(True)
        self.txt_report_preview.setMaximumBlockCount(2000)
        preview_layout.addWidget(self.txt_report_preview)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        # 底部：导出按钮
        export_row = QHBoxLayout()
        self.lbl_report_kind_hint = QLabel("未生成报告")
        self.lbl_report_kind_hint.setStyleSheet(f"color:{GRAY};")
        export_row.addWidget(self.lbl_report_kind_hint)
        export_row.addStretch()
        self.btn_report_export_docx = QPushButton("📝 导出 DOCX")
        self.btn_report_export_docx.setStyleSheet(
            "QPushButton { background:#2E5BBA; color:#fff; padding:8px 16px; border-radius:4px; }")
        self.btn_report_export_pdf = QPushButton("📕 导出 PDF")
        self.btn_report_export_pdf.setStyleSheet(
            "QPushButton { background:#7B5CFA; color:#fff; padding:8px 16px; border-radius:4px; }")
        self.btn_report_export_json = QPushButton("💾 导出 JSON")
        self.btn_report_export_json.setStyleSheet(
            "QPushButton { background:#3E7BFA; color:#fff; padding:8px 16px; border-radius:4px; }")
        export_row.addWidget(self.btn_report_export_docx)
        export_row.addWidget(self.btn_report_export_pdf)
        export_row.addWidget(self.btn_report_export_json)
        layout.addLayout(export_row)

        self._current_report = None      # 原始字段（供 JSON 导出）
        self._current_block = None       # 渲染块模型（供 DOCX/PDF 导出）
        # 连接信号
        self.btn_report_refresh.clicked.connect(self._refresh_report_list)
        self.btn_report_generate.clicked.connect(self._generate_report)
        self.btn_report_export_docx.clicked.connect(lambda: self._export_report_file("docx"))
        self.btn_report_export_pdf.clicked.connect(lambda: self._export_report_file("pdf"))
        self.btn_report_export_json.clicked.connect(self._export_report_json)

    def _refresh_report_list(self):
        """刷新报告页的链上存证列表。"""
        try:
            history = self.svc.list_chain_evidence()
        except Exception as exc:
            self.log(f"✖ 加载存证列表失败：{exc}", module="report")
            return
        self.tbl_report_evidence.setSortingEnabled(False)
        self.tbl_report_evidence.setRowCount(len(history))
        for row, item in enumerate(history):
            self.tbl_report_evidence.setItem(row, 0, QTableWidgetItem(item.get("file_id") or ""))
            ev_no = item.get("evidence_no") or ""
            self.tbl_report_evidence.setItem(row, 1, QTableWidgetItem(short(ev_no, 14, 6)))
            self.tbl_report_evidence.setItem(row, 2, QTableWidgetItem(item.get("file_name") or ""))
            ts = item.get("timestamp")
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""
            self.tbl_report_evidence.setItem(row, 3, QTableWidgetItem(ts_str))
            # 把完整 evidence_no 存到第一列的 UserRole
            self.tbl_report_evidence.item(row, 0).setData(Qt.UserRole, ev_no)
        self.tbl_report_evidence.setSortingEnabled(True)
        self.log(f"报告页已加载 {len(history)} 条链上存证", module="report")

    def _selected_report_evidence_no(self):
        row = self.tbl_report_evidence.currentRow()
        if row < 0:
            return None
        item = self.tbl_report_evidence.item(row, 0)
        return item.data(Qt.UserRole) if item else None

    @staticmethod
    def _render_report_preview(block):
        """把报告块模型渲染成纯文本预览（与 DOCX/PDF 同源，避免预览与导出口径不一致）。"""
        lines = ["═" * 30, block["title"], block["subtitle"], "═" * 30]
        for k, v in block.get("meta", []):
            lines.append(f"{k}：{v}")
        for title, rows in block.get("sections", []):
            lines.append("")
            lines.append(f"【{title}】")
            for k, v in rows:
                lines.append(f"{k}：{v}")
        lines.append("")
        lines.append(f"【{block['conclusion_label']}】{block['conclusion']}")
        if block.get("statement"):
            lines.append("")
            lines.append("【声明】")
            lines.extend(block["statement"])
        return "\n".join(lines)

    def _generate_report(self):
        ev_no = self._selected_report_evidence_no()
        if not ev_no:
            self.log("⚠ 请先在列表中选中一条存证", module="report")
            dialogs.info(self, "提示", "请先在「链上存证列表」中选中一条存证。")
            return
        kind = self.cmb_report_kind.currentData()
        label = self.cmb_report_kind.currentText()

        candidate = None
        if kind == "proof" and self.chk_report_file.isChecked():
            path, _ = QFileDialog.getOpenFileName(
                self, "选择待核验的原文件（用于重算 SM3 指纹）", "", "所有文件 (*)")
            if path:
                try:
                    with open(path, "rb") as f:
                        candidate = f.read()
                except OSError as exc:
                    self.log(f"✖ 读取原文件失败：{exc}", module="report")
                    return

        self.log(f"📄 生成{label}：{short(ev_no, 12, 6)} ...", module="report")
        try:
            if kind == "receipt":
                data = self.svc.receipt_report(ev_no)
                block = report_export.build_receipt(data)
            else:
                data = self.svc.proof_report(ev_no, candidate)
                block = report_export.build_proof(data)
        except Exception as exc:
            self.log(f"✖ 报告生成失败：{type(exc).__name__}: {exc}", module="report")
            dialogs.warn(self, "生成失败", f"{type(exc).__name__}: {exc}")
            return

        self._current_report = data
        self._current_block = block
        self.txt_report_preview.setPlainText(self._render_report_preview(block))
        self.lbl_report_kind_hint.setText(f"当前：{block['title']}（{ev_no}）")

        if kind == "proof":
            verdict = ("通过" if data["passed"] else
                       ("部分核验（内容一致性未核验）" if data.get("conclusion_ok") is None else "未通过"))
            self.log(f"✅ 证据报告已生成，核验结论：{verdict}；已含 {len(block['sections'])} 个章节",
                     module="report")
        else:
            self.log(f"✅ 存证凭证已生成，凭证编号 {data['凭证编号']}", module="report")

    def _export_report_file(self, ext: str):
        """导出当前报告为 DOCX / PDF；两种模板各自成文，不复用同一份内容。"""
        if not self._current_block:
            self.log("⚠ 请先生成报告", module="report")
            dialogs.info(self, "提示", "请先点击「生成选中存证的报告」。")
            return
        block = self._current_block
        ev_no = (self._current_report or {}).get("存证编号", "")
        suggested = report_export.suggest_name(block, ev_no) + "." + ext
        filt = "Word 文档 (*.docx)" if ext == "docx" else "PDF 文档 (*.pdf)"
        path, _ = QFileDialog.getSaveFileName(self, f"导出{block['title']}", suggested, filt)
        if not path:
            return
        if not path.lower().endswith("." + ext):
            path += "." + ext
        try:
            report_export.export(block, path)
        except Exception as exc:
            self.log(f"✖ 导出失败：{type(exc).__name__}: {exc}", module="report")
            dialogs.warn(self, "导出失败", f"{type(exc).__name__}: {exc}")
            return
        self.log(f"✅ {ext.upper()} 已导出：{path}", module="report")

    def _export_report_json(self):
        if not self._current_report:
            self.log("⚠ 请先生成报告", module="report")
            return
        import json as _json
        block = self._current_block or {"kind": "receipt"}
        suggested = report_export.suggest_name(block, self._current_report.get("存证编号", "")) + ".json"
        path, _ = QFileDialog.getSaveFileName(self, "导出报告 JSON", suggested, "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(self._current_report, f, ensure_ascii=False, indent=2)
            self.log(f"✅ JSON 报告已保存：{path}", module="report")
        except OSError as exc:
            self.log(f"✖ 保存失败：{exc}", module="report")

    # ------------------------------------------------------------- 日志/线程
    # 日志模块定义：用于分区展示与持久化
    LOG_MODULES = ("system", "auth", "evidence", "verify",
                   "search", "decrypt", "user", "report")
    LOG_MODULE_LABELS = {
        "system": "系统", "auth": "登录/鉴权", "evidence": "存证签署",
        "verify": "验真溯源", "search": "存证检索", "decrypt": "授权解密",
        "user": "用户管理", "report": "存证报告",
    }

    def log(self, msg: str, module: str = "system"):
        """只写持久化日志并按需刷新独立日志页，不再向业务页输出。"""
        try:
            self.svc.log_entry(module, msg)
        except Exception:
            pass
        if getattr(self, "tbl_logs", None) is not None and self.tabs.currentWidget() is self.tab_logs:
            self._refresh_log_view()

    def _refresh_log_view(self):
        """刷新独立日志页：按当前角色权限范围 + 模块筛选加载。"""
        if getattr(self, "tbl_logs", None) is None:
            return
        module = self.cmb_log_module.currentData()
        try:
            entries = self.svc.list_logs(module=module, limit=200)
        except Exception as exc:
            self.lbl_logs_msg.setText(f"日志加载失败：{exc}")
            return
        self.tbl_logs.setSortingEnabled(False)
        self.tbl_logs.setRowCount(len(entries))
        for row, e in enumerate(entries):
            created = (e.get("created_at") or "").replace("T", " ")
            self.tbl_logs.setItem(row, 0, QTableWidgetItem(created[:19]))
            self.tbl_logs.setItem(row, 1, QTableWidgetItem(
                self.LOG_MODULE_LABELS.get(e.get("module"), e.get("module") or "")))
            self.tbl_logs.setItem(row, 2, QTableWidgetItem(e.get("operator") or "系统"))
            self.tbl_logs.setItem(row, 3, QTableWidgetItem(e.get("message") or ""))
        self.tbl_logs.setSortingEnabled(True)
        user = self.svc.current_user()
        role = user["role"] if user else None
        scope = "全部日志" if role == "superadmin" else (
            "本人操作日志 + 系统日志" if role == "admin" else "本人操作日志")
        self.lbl_logs_msg.setText(f"当前可见范围：{scope}；共 {len(entries)} 条")
        bar = self.tbl_logs.verticalScrollBar()
        bar.setValue(0)

    def _clear_logs(self):
        """按权限清空日志：superadmin 清空全部，其余角色仅清空本人操作日志。"""
        user = self.svc.current_user()
        if not user:
            return
        role = user["role"]
        scope = "全部日志" if role == "superadmin" else "本人操作日志"
        if not dialogs.confirm(
                self, "清空日志", f"确认清空{scope}？（此操作不可撤销）"):
            return
        try:
            n = self.svc.clear_logs()
        except (PermissionError, Exception) as exc:
            self.lbl_logs_msg.setText(f"清空失败：{exc}")
            return
        self._refresh_log_view()
        self.lbl_logs_msg.setText(f"已清空{scope} {n} 条")

    def _start_worker(self, fn, on_ok):
        worker = Worker(fn, self)
        worker.ok.connect(on_ok)
        worker.fail.connect(lambda msg: self.log(f"✖ 后台任务失败：{msg}", module="system"))
        self._workers.append(worker)
        worker.start()

    # ---------------------------------------------------------- 存证与签署
    def on_sign_file(self, name, data):
        self.tab1_file = (name, data)
        self.lbl_sign_digest.setText("SM3 指纹：计算中…")
        self.log(f"载入文件 [{name}]（{len(data):,} 字节），后台计算 SM3 指纹…", module="evidence")
        self._start_worker(lambda: cc.sm3_hash(data), self._on_sign_digest)

    def _on_sign_digest(self, digest):
        if not self.tab1_file:
            return
        name, data = self.tab1_file
        self.tab1_file = (name, data, digest)
        self.lbl_sign_digest.setText(f"SM3 指纹：{digest}")
        self.log(f"SM3 指纹计算完成：{digest}", module="evidence")

    def on_sign(self):
        if not self.tab1_file or len(self.tab1_file) < 3:
            self.log("⚠ 请先上传文件，并等待 SM3 指纹计算完成后再签署", module="evidence")
            return
        if self.uploader is None:
            self.log("⚠ 账号密钥未就绪 —— 请确认已成功登录；若密钥文件损坏请删除 ~/.xincain/keystore/ 下对应文件后重新登录", module="evidence")
            return
        # 每次签署弹出「存证授权口令」对话框；取消则中止，口令不足 6 位在弹窗内即时拦截
        dlg = PassphraseDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            self.log("（已取消签署：未设置存证授权口令）", module="evidence")
            return
        passphrase = dlg.passphrase()
        name, data, digest = self.tab1_file
        self._file_counter += 1
        file_id = f"FILE-{self._file_counter:03d}"

        self.log("―――― 开始签署（使用当前登录账号 SM2 密钥 + PBKDF2 口令加密原文）――――", module="evidence")
        self.log(f"① SM3 指纹（原文不上链）：{digest}", module="evidence")
        self.log(f"①-2 签名主体（账号公钥指纹）：{self.uploader.pubkey_fingerprint}", module="evidence")

        receipt = self.svc.submit_file(
            file_id, name, data, self.uploader, passphrase,
            meta={"文件名": name, "大小": f"{len(data):,} 字节"},
        )["receipt"]
        ev_no = receipt["evidence_no"]
        tx = self.chain.query_evidence(ev_no)["transaction"]

        self.log(f"② 签名载荷（file_id|指纹|时间戳）："
                 f"{file_id}|{short(tx['contract_hash'], 12, 6)}|{tx['ts']:.2f}", module="evidence")
        self.log(f"③ 上传方 SM2 私钥签名（r‖s，128 位 hex）：{short(tx['signature'], 24, 16)}", module="evidence")
        self.log(f"④ 广播至联盟链 → 共识确认 {receipt['confirmations']}/{len(self.chain.nodes)}，"
                 f"出块节点 {receipt['validator']}", module="evidence")
        self.log(f"⑤ 上链完成：存证号 {ev_no}，区块 #{receipt['block_index']}", module="evidence")
        self._update_status_bar()

        self.lbl_sign_result.setText(
            f"✅ 已上链：{name}\n"
            f"存证号：{ev_no}\n"
            f"区块 #{receipt['block_index']} ｜ 出块节点 {receipt['validator']}"
            f" ｜ 确认数 {receipt['confirmations']}\n"
            f"签名值：{short(tx['signature'], 24, 16)}"
        )
        self._signed_file = (name, data)
        self._last_file_id = file_id
        self._register_evidence(ev_no, name)

        # AI 语义索引：加密前由 GLM 生成摘要/关键词/分类，存证完成后即时回显到界面
        try:
            summary, keywords, category = self.svc._semantic_of(tx["contract_hash"])
            if summary or keywords:
                ai_line = "🧠 AI 语义索引：%s" % (summary or "（仅关键词索引）")
                if keywords:
                    ai_line += " ｜ 关键词 " + "、".join(keywords[:5])
                if category:
                    ai_line += " ｜ 分类 " + category
                self.log(ai_line, module="evidence")
                self.lbl_sign_result.setText(
                    self.lbl_sign_result.text() + "\nAI 语义：" + (summary or "、".join(keywords[:5]))
                )
            if hasattr(self, "_refresh_ai_page"):
                self._refresh_ai_page()
        except Exception as exc:
            self.log(f"⚠ AI 语义索引回显失败（不影响存证）：{exc}", module="evidence")

    def on_countersign(self):
        if self._signed_file is None:
            self.log("⚠ 尚无已签署文件，请先点击「签署并上链」", module="evidence")
            return
        name, data = self._signed_file
        result = self.svc.add_signer(self._last_file_id, name, data, self.auditor)
        ev_no = result["receipt"]["evidence_no"]
        self.log(f"审计方追加签认完成：主体 {result['signer']}，存证号 {ev_no}", module="evidence")
        self._register_evidence(ev_no, f"{name}（审计签认）")

    def _register_evidence(self, ev_no, filename, quiet=False):
        label = f"{short(ev_no, 12, 6)} ｜ {filename}"
        self.cmb_evidence.addItem(label, ev_no)
        self.cmb_evidence.setCurrentIndex(self.cmb_evidence.count() - 1)
        if not quiet:
            self.log(f"存证已加入验真列表：{label}", module="evidence")

    def _load_history(self):
        """启动时从本地快照恢复的历史链上存证：回填验真下拉框，避免重启后看不到历史。"""
        history = self.svc.list_chain_evidence()
        if not history:
            return
        max_no = 0
        for item in history:
            self._register_evidence(item["evidence_no"], item["file_name"], quiet=True)
            tail = (item.get("file_id") or "").rsplit("-", 1)[-1]
            if tail.isdigit():
                max_no = max(max_no, int(tail))
        self._file_counter = max_no           # 续编号，避免新存证 file_id 与历史冲突
        if self.cmb_evidence.count():
            self.cmb_evidence.setCurrentIndex(self.cmb_evidence.count() - 1)
        self.log(f"已从本地快照恢复 {len(history)} 条历史链上存证，链高度 {self.chain.height()}"
                 "（重启不再丢失，可直接验真 / 解密）", module="system")

    # --------------------------------------------- 页面导航 / 登录态
    def _goto_page(self, index: int):
        """跳转页面：整页覆盖显示，不做多标签并列。带页访问守卫。"""
        # 页访问守卫：users 页仅 superadmin；logs 页对所有登录用户开放（内容仍按 user_id 隔离）
        user = self.svc.current_user()
        role = user["role"] if user else None
        if index == self.tabs.indexOf(self.tab_users) and role != "superadmin":
            dialogs.warn(self, "无权限", "仅超级管理员可访问用户权限管理页")
            return
        self.tabs.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        if self.tabs.currentWidget() is self.tab_search:
            # 进入检索页默认做一次空检索，展示当前登录用户可查看的存证列表
            self.edt_search.clear()
            self.on_search(quiet=True)
        elif self.tabs.currentWidget() is self.tab_report:
            # 进入报告页自动刷新链上存证列表
            self._refresh_report_list()
        elif self.tabs.currentWidget() is getattr(self, "tab_ai", None):
            # 进入 AI 语义页刷新引擎状态与索引列表
            self._refresh_ai_page()
        elif self.tabs.currentWidget() is self.tab_logs:
            # 进入日志页刷新历史日志
            self._refresh_log_view()

    def _apply_session(self, announce=True, password=None):
        """把当前登录用户同步到标题、导航栏、账号密钥、用户中心与权限页可见性。"""
        user = self.svc.current_user()
        if not user:
            # 登出态：清空账号密钥与 uploader
            self._account_signer = None
            self.uploader = None
            self.lbl_uploader_id.setText("上传方公钥指纹：待登录后加载账号密钥")
            return

        role = ROLE_NAMES.get(user["role"], user["role"])
        self.setWindowTitle(f"信链 · 国密电子文件存证系统 · {user['display_name']}")
        self.lbl_nav_user.setText(f"{user['username']} · {role}")
        self.lbl_center_username.setText(user["username"])
        self.lbl_center_display.setText(user["display_name"] or "—")
        self.lbl_center_role.setText(role)
        self.lbl_center_status.setText(STATUS_NAMES.get(user["status"], user["status"]))
        created = (user.get("created_at") or "").replace("T", " ")[:19]
        self.lbl_center_created.setText(created or "—")

        # 加载 / 生成本地账号密钥（password 由 LoginDialog 登录成功时传入）
        if password and self._account_signer is None:
            try:
                self._account_signer = self._keystore.load_or_generate(user["username"], password)
                self.uploader = self._account_signer
                self.lbl_uploader_id.setText(
                    f"上传方公钥指纹：{self.uploader.pubkey_fingerprint}（账号 {user['username']}）")
                self.log(
                    f"🔐 已为账号 [{user['username']}] {'加载' if self._keystore.exists(user['username']) else '生成'} "
                    f"专属 SM2 密钥对（本地加密文件：{self._keystore._path(user['username'])}，"
                    f"公钥指纹 {self._account_signer.pubkey_fingerprint}）",
                    module="auth"
                )
            except ValueError as exc:
                self.log(f"⚠ 账号密钥加载失败：{exc}；存证将无法使用本账号签名", module="auth")
                self._account_signer = None
                self.uploader = None
        elif self._account_signer is not None:
            self.uploader = self._account_signer
            self.lbl_uploader_id.setText(
                f"上传方公钥指纹：{self.uploader.pubkey_fingerprint}（账号 {user['username']}）")

        # ---- 导航可见性矩阵（按角色控制 8 个导航按钮显隐） ----
        role = user["role"]
        is_super = role == "superadmin"
        is_admin_or_above = role in ("admin", "superadmin")
        # superadmin: 全部可见；admin / user: 隐藏 users；logs 对所有角色可见（内容按 user_id 隔离）
        self.btn_nav_users.setVisible(is_super)
        self.btn_nav_logs.setVisible(True)
        # sign / verify / search / decrypt / report / center 所有角色均可见

        # ---- 用户管理页操作按钮按角色细化 ----
        # superadmin: 可改角色、启停/删除、重置密码；admin: 仅可重置密码
        admin_only_btns = (self.btn_make_admin, self.btn_make_user,
                           self.btn_enable_user, self.btn_disable_user,
                           self.btn_delete_user)
        for btn in admin_only_btns:
            btn.setEnabled(is_super)
        self.btn_reset_user_pwd.setEnabled(is_admin_or_above)

        if is_super:
            self._setup_user_admin()
            self._refresh_users()
        elif self.tabs.currentWidget() is self.tab_users:
            self._goto_page(0)

        # ---- 中心页统计：按角色展示可查看范围的存证统计 ----
        self._refresh_center_stats()
        self._update_status_bar()

        if self.tabs.currentWidget() is self.tab_search:
            self.on_search(quiet=True)         # 登录态变化后刷新「可查看存证」列表
        if announce:
            self.log(f"当前登录用户：{user['display_name']}（{user['username']} / {role}），"
                     "本次存证将归属该账号", module="auth")

    def _change_password(self):
        """打开修改密码独立弹窗，校验通过后调用 service 改密。"""
        user = self.svc.current_user()
        if not user:
            dialogs.warn(self, "修改密码", "请先登录后再修改密码")
            return
        dlg = dialogs.ChangePasswordDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        old, new = dlg.values()
        try:
            self.svc.change_password(old, new)
        except (PermissionError, ValueError) as exc:
            dialogs.warn(self, "修改密码失败", str(exc))
            return
        except Exception as exc:
            dialogs.warn(self, "修改密码失败", f"{type(exc).__name__}: {exc}")
            return
        dialogs.info(self, "修改密码", "密码修改成功，下次登录请使用新密码")
        self.log(f"账号 {user['username']} 修改密码成功（PBKDF2 重新加盐哈希）", module="auth")

    def _reset_ui_for_login(self):
        """登出后清空所有业务页残留数据，复位到登录前的干净状态，再弹出登录框。"""
        # 基本登录态复位：清空账号密钥与上传方指纹（current_user 已为 None）
        self._apply_session(announce=False)

        # 顶栏用户标签与窗口标题复位
        self.lbl_nav_user.setText("未登录")
        self.setWindowTitle("信链 · 未登录")

        # 导航可见性复位：未登录时隐藏「用户权限管理」，其余入口可见
        self.btn_nav_users.setVisible(False)
        for btn in self._nav_buttons:
            if btn is not self.btn_nav_users:
                btn.setVisible(True)

        # 清空各业务表数据，避免上一账号的残留数据被下一账号看到
        for tbl in (self.tbl_search_results, self.tbl_logs,
                    self.tbl_report_evidence, self.tbl_users):
            tbl.setRowCount(0)

        # 清空验真下拉与结论行
        self.cmb_evidence.clear()
        self._reset_rows()

        # 用户中心统计标签复位
        if hasattr(self, "lbl_stats_scope"):
            self.lbl_stats_scope.setText("统计范围：—")
        for attr in ("lbl_stats_mine", "lbl_stats_evidence",
                     "lbl_stats_recent", "lbl_stats_users",
                     "lbl_stats_placeholder"):
            lbl = getattr(self, attr, None)
            if lbl is not None:
                lbl.setText("—")
        if hasattr(self, "lbl_center_avatar"):
            self.lbl_center_avatar.setText("●")
        if hasattr(self, "lbl_center_role_badge"):
            self.lbl_center_role_badge.setText("")
        if hasattr(self, "_card_placeholder"):
            self._card_placeholder.setVisible(False)

        # 清空检索 / 解密结果与输入
        self.edt_search.clear()
        self.lbl_search_summary.setText("当前显示可查看的 0 条存证")
        self.edt_decrypt_file_id.clear()
        self.edt_decrypt_passphrase.clear()
        self.lbl_decrypt_result.setText("— 输入 file_id + 口令后点击按钮 —")
        self.lbl_decrypt_result.setStyleSheet(f"color:{GRAY}; padding:6px;")
        self._last_recovered = None
        self.btn_save_recovered.setEnabled(False)

        # 清空报告预览
        if hasattr(self, "txt_report_preview"):
            self.txt_report_preview.clear()
        self._current_report = None

        # 复位到首页并刷新状态栏
        self._goto_page(0)
        self._update_status_bar()

    def _logout(self):
        user = self.svc.current_user()
        if not user:
            return
        if not dialogs.confirm(
                self, "退出登录", "退出后需要重新输入账号密码，确定继续？"):
            return
        self.log(f"用户 {user['display_name']} 退出登录", module="auth")
        self.svc.logout()
        self._reset_ui_for_login()          # 清空业务页残留，避免下一账号看到上一账号数据
        dlg = LoginDialog(self.svc, self)
        if dlg.exec_() != QDialog.Accepted:
            self.close()
            return
        self._apply_session(password=dlg._last_password)
        self._goto_page(0)

    # --------------------------------------------- 用户权限管理（仅超级管理员）
    def _setup_user_admin(self):
        """配置用户列表；重复调用安全（登出换账号后不会重复建列）。"""
        if self._admin_ready:
            return

        self.tbl_users.setColumnCount(4)
        self.tbl_users.setHorizontalHeaderLabels(["用户名", "角色", "状态", "创建时间"])
        self.tbl_users.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_users.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl_users.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_users.verticalHeader().setVisible(False)
        self.tbl_users.horizontalHeader().setStretchLastSection(True)
        self.tbl_users.setColumnWidth(0, 160)
        self.tbl_users.setColumnWidth(1, 100)
        self.tbl_users.setColumnWidth(2, 80)
        self._admin_ready = True

    def _refresh_users(self):
        try:
            users = self.svc.list_users()
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"无法加载用户列表：{exc}", ok=False)
            return
        self.tbl_users.setSortingEnabled(False)
        self.tbl_users.setRowCount(len(users))
        for row, u in enumerate(users):
            name_item = QTableWidgetItem(u["username"])
            name_item.setData(Qt.UserRole, u["username"])
            self.tbl_users.setItem(row, 0, name_item)
            self.tbl_users.setItem(row, 1, QTableWidgetItem(
                ROLE_NAMES.get(u["role"], u["role"])))
            self.tbl_users.setItem(row, 2, QTableWidgetItem(
                STATUS_NAMES.get(u["status"], u["status"])))
            created = (u.get("created_at") or "").replace("T", " ")[:19]
            self.tbl_users.setItem(row, 3, QTableWidgetItem(created))
        self.tbl_users.setSortingEnabled(True)
        self._set_users_msg(
            f"共 {len(users)} 个账号；选中一行后可调整角色 / 启用或停用 / 重置密码 / 删除",
            ok=True)

    def _change_user_role(self, role):
        item = self.tbl_users.currentItem()
        if item is None:
            self._set_users_msg("请先在列表中选择要调整的用户", ok=False)
            return
        username = self.tbl_users.item(item.row(), 0).text()
        role_name = ROLE_NAMES.get(role, role)
        if not dialogs.confirm(
                self, "确认修改权限", f"确定将用户「{username}」设为{role_name}？"):
            return
        try:
            info = self.svc.set_user_role(username, role)
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"修改失败：{exc}", ok=False)
            self.log(f"权限变更失败：{username} → {role_name}（{exc}）", module="user")
            return
        new_role = ROLE_NAMES.get(info["role"], info["role"])
        self._refresh_users()
        self._set_users_msg(f"已将「{username}」设为{new_role}", ok=True)
        self.log(f"权限变更：{username} → {new_role}", module="user")

    def _selected_username(self):
        """取用户列表当前选中行的用户名；未选中时提示并返回 None。"""
        item = self.tbl_users.currentItem()
        if item is None:
            self._set_users_msg("请先在用户列表中选择一行", ok=False)
            return None
        return self.tbl_users.item(item.row(), 0).text()

    def _change_user_status(self, status):
        """启用 / 停用选中账号（仅超级管理员可操作，服务层二次校验权限）。"""
        username = self._selected_username()
        if not username:
            return
        label = "启用" if status == "enabled" else "停用"
        extra = "" if status == "enabled" else "（停用后该账号将无法登录）"
        if not dialogs.confirm(
                self, f"确认{label}", f"确定{label}账号「{username}」？{extra}"):
            return
        try:
            self.svc.set_user_status(username, status)
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"{label}失败：{exc}", ok=False)
            self.log(f"账号{label}失败：{username}（{exc}）", module="user")
            return
        self._refresh_users()
        self._set_users_msg(f"已{label}账号「{username}」", ok=True)
        self.log(f"账号状态变更：{username} → {STATUS_NAMES.get(status, status)}", module="user")

    def _delete_user(self):
        """删除选中账号（二次确认；存证本体保留，归属清空）。"""
        username = self._selected_username()
        if not username:
            return
        if not dialogs.confirm(
                self, "确认删除用户",
                f"确定永久删除账号「{username}」？\n\n"
                "• 该账号的登录态立即失效\n"
                "• 其存证记录本体保留，仅清空归属（上传账号显示为未登录匿名存证）\n"
                "• 此操作不可撤销"):
            return
        try:
            self.svc.delete_user(username)
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"删除失败：{exc}", ok=False)
            self.log(f"删除用户失败：{username}（{exc}）", module="user")
            return
        self._refresh_users()
        self._set_users_msg(f"已删除账号「{username}」（存证记录保留）", ok=True)
        self.log(f"删除用户：{username}（账号已物理删除，存证本体保留、归属清空）", module="user")

    def _reset_user_password(self):
        """为选中账号代重置密码（无需原密码，重置后其登录态失效）。"""
        username = self._selected_username()
        if not username:
            return
        dlg = ResetPasswordDialog(username, self)
        if dlg.exec_() != QDialog.Accepted:
            self.log(f"（已取消重置密码：{username}）", module="user")
            return
        try:
            self.svc.reset_password(username, dlg.new_password())
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"重置密码失败：{exc}", ok=False)
            self.log(f"重置密码失败：{username}（{exc}）", module="user")
            return
        self._refresh_users()
        self._set_users_msg(f"已重置账号「{username}」的密码", ok=True)
        self.log(f"重置密码：{username}（PBKDF2 重新加盐哈希，其登录态已失效）", module="user")

    def _set_users_msg(self, text, ok=True):
        self.lbl_users_msg.setText(text)
        self.lbl_users_msg.setStyleSheet(f"color:{GREEN if ok else RED};")

    # ------------------------------------------------------- 验真与攻击演示
    def on_verify_file(self, name, data):
        self.tab2_file = (name, data)
        self.lbl_verify_digest.setText("本地 SM3 指纹：计算中…")
        self.log(f"验真页载入文件 [{name}]（{len(data):,} 字节），计算 SM3 指纹…", module="verify")
        self._start_worker(lambda: cc.sm3_hash(data), self._on_verify_digest)

    def _on_verify_digest(self, digest):
        self.lbl_verify_digest.setText(f"本地 SM3 指纹：{digest}")
        self.log(f"验真文件 SM3 指纹：{digest}", module="verify")

    def _selected_evidence(self):
        ev_no = self.cmb_evidence.currentData()
        if not ev_no:
            self.log("⚠ 链上暂无存证记录，请先在「存证与签署」页完成签署", module="verify")
        return ev_no

    def _candidate(self):
        if self.tab2_file:
            return self.tab2_file[1]
        if self.tab1_file and len(self.tab1_file) >= 3:
            self.log("（验真页未载入文件，自动使用存证页当前文件）", module="verify")
            return self.tab1_file[1]
        self.log("⚠ 请先载入待验真的文件", module="verify")
        return None

    def _reset_rows(self):
        for name in self.rows:
            if name == "审计方签名":
                continue          # 审计方行仅有实际签认时显示，复位时清空并隐藏
            self._set_row(name, None, "待检测")
        self.row_auditor.setText("")
        self.row_auditor.setVisible(False)
        self.lbl_conclusion.setText("结论：—")
        self.lbl_conclusion.setStyleSheet("")

    def _set_row(self, name, state, msg):
        """state: True=通过(绿) / False=失败(红) / None=未检测(灰)"""
        label = self.rows[name]
        if state is None:
            label.setText(f'<span style="color:{GRAY};">○ <b>{name}</b>：{msg}</span>')
        else:
            color = GREEN if state else RED
            icon = OK_ICON if state else BAD_ICON
            label.setText(f'<span style="color:{color};">{icon} <b>{name}</b>：{msg}</span>')

    def _apply_verify(self, v):
        checks = v["checks"]
        self._set_row("链上存证", checks["链上存证"].startswith("通过"),
                      checks["链上存证"].splitlines()[0])
        self._set_row("完整性(SM3)", checks["完整性(SM3)"].startswith("通过"),
                      checks["完整性(SM3)"].splitlines()[0])
        if "签名(SM2)" in checks:
            self._set_row("签名(SM2)", checks["签名(SM2)"].startswith("通过"),
                          checks["签名(SM2)"].splitlines()[0])
        else:
            self._set_row("签名(SM2)", None, "未检测（完整性已失败）")
        # 审计方签名验证：仅有实际签认（通过/失败）时才显示该行；无签认则整行隐藏
        audit_msg = checks.get("审计方签名", "")
        if audit_msg.startswith("通过"):
            self._set_row("审计方签名", True, audit_msg.splitlines()[0])
            self.row_auditor.setVisible(True)
        elif audit_msg.startswith("失败"):
            self._set_row("审计方签名", False, audit_msg.splitlines()[0])
            self.row_auditor.setVisible(True)
        else:
            self.row_auditor.setVisible(False)
        if v["passed"]:
            multi = v.get("multi_sign_ok", False)
            if multi:
                tail = "；多方签认闭环达成（上传方 + 审计方均有效）"
            else:
                tail = "；暂无审计方追加签认（多方签认未闭环）"
            self.lbl_conclusion.setText(
                f"🎉 验真通过：文件完整、签名有效、存证可信{tail}")
            self.lbl_conclusion.setStyleSheet(f"color:{GREEN}; font-weight:bold; font-size:15px;")
        else:
            self.lbl_conclusion.setText(f"❌ 验真未通过：{v.get('reason', '校验失败')}")
            self.lbl_conclusion.setStyleSheet(f"color:{RED}; font-weight:bold; font-size:15px;")

    def on_verify(self):
        ev_no = self._selected_evidence()
        if not ev_no:
            return
        data = self._candidate()
        if data is None:
            return
        self.log(f"――― 三重验真：{short(ev_no, 12, 6)} ―――", module="verify")
        result = self.svc.verify(ev_no, data)
        self._apply_verify(result)
        self.log("验真结论：" + ("通过 ✅" if result["passed"]
                                else f"未通过 ❌（{result.get('reason', '')}）"), module="verify")

    def on_tamper(self):
        ev_no = self._selected_evidence()
        if not ev_no:
            return
        data = self._candidate()
        if data is None:
            return
        tampered = data[:-1] + bytes([data[-1] ^ 0xFF])
        self.log("攻击模拟：翻转文件最后 1 个字节（异或 0xFF）", module="verify")
        result = self.svc.verify(ev_no, tampered)
        self._apply_verify(result)
        if not result["passed"]:
            self.log(f"攻击结果：篡改被识别 ❌ —— {result.get('reason', '')}", module="verify")

    def on_forge(self):
        ev_no = self._selected_evidence()
        if not ev_no:
            return
        tx = self.chain.query_evidence(ev_no)["transaction"]
        file_id = tx["extra"].split("|")[0]
        payload = f"{file_id}|{tx['contract_hash']}|{tx['ts']}".encode()

        forger = cc.Signer.generate()
        forged = forger.sign(payload)
        verifier = cc.Signer.from_public_key(tx["pubkey"])
        valid = verifier.verify(forged, payload)

        self.log("攻击模拟：攻击者用自己的私钥对同一载荷签名，冒充上传方", module="verify")
        self.log(f"伪造者公钥指纹：{forger.pubkey_fingerprint}", module="verify")
        self.log(f"用真实上传方公钥验签伪造签名 → {'通过（异常！）' if valid else '失败'}，冒充被识破", module="verify")

        on_chain = self.chain.query_evidence(ev_no)
        self._set_row("链上存证", True, f"通过：存在，区块 #{on_chain['block']['index']}")
        self._set_row("完整性(SM3)", True, "通过：文件未被篡改")
        self._set_row("签名(SM2)", False, "失败：伪造签名无效（签名主体不可信）")
        self.row_auditor.setVisible(False)   # 攻击演示场景不涉及审计方签认
        self.lbl_conclusion.setText("🛡 攻击被拦截：伪造签名无法通过真实上传方公钥验签 —— 不可否认性有效")
        self.lbl_conclusion.setStyleSheet("font-weight:bold; font-size:15px;")

    # ---------------------------------------------- 关键词检索（P0-2 + P0-5 方案 B）
    def on_search(self, quiet=False):
        """检索：空检索词列出可查看范围全部存证；有关键词则在可查看范围内过滤。"""
        query = self.edt_search.text().strip()
        self.tbl_search_results.setRowCount(0)
        try:
            results = self.svc.search_evidence(query)
        except Exception as exc:
            self.lbl_search_summary.setText("检索失败，请查看日志")
            self.log(f"✖ 检索失败：{type(exc).__name__}: {exc}", module="search")
            return
        self.tbl_search_results.setRowCount(len(results))
        for row, r in enumerate(results):
            item0 = QTableWidgetItem(r.get("file_id") or "")
            item0.setData(Qt.UserRole, r)
            self.tbl_search_results.setItem(row, 0, item0)
            ev_no = r.get("evidence_no")
            self.tbl_search_results.setItem(
                row, 1, QTableWidgetItem(short(ev_no, 14, 6) if ev_no else "（本机未上链）"))
            self.tbl_search_results.setItem(row, 2, QTableWidgetItem(r.get("file_name") or r.get("file_id") or ""))
            self.tbl_search_results.setItem(row, 3, QTableWidgetItem(r.get("uploader_username") or "匿名"))
            self.tbl_search_results.setItem(row, 4, QTableWidgetItem(short(r.get("file_sha256") or "", 14, 6)))
            # 匹配方式：区分「向量语义召回」与「关键词命中」，让 AI 参与在界面上可见
            kind = r.get("match")
            if kind == "vector":
                cell = QTableWidgetItem("语义 %.2f" % float(r.get("score") or 0))
                cell.setForeground(QBrush(QColor("#1DC981")))
            elif query:
                cell = QTableWidgetItem("关键词")
                cell.setForeground(QBrush(QColor(GRAY)))
            else:
                cell = QTableWidgetItem("—")
                cell.setForeground(QBrush(QColor(GRAY)))
            self.tbl_search_results.setItem(row, 5, cell)
        if query:
            vector_n = sum(1 for r in results if r.get("match") == "vector")
            summary = f"「{query}」命中的 {len(results)} 条存证（当前可查看范围内）"
            if vector_n:
                summary += f"，其中 {vector_n} 条来自向量语义召回"
            if not quiet:
                if vector_n:
                    self.log(f"🔍 语义检索：「{query}」命中 {len(results)} 条（向量语义 {vector_n} 条）",
                             module="search")
                else:
                    self.log(f"🔍 关键词检索：「{query}」（按当前登录用户权限过滤）", module="search")
        else:
            summary = f"当前显示可查看的 {len(results)} 条存证"
            if not quiet:
                self.log(f"📋 已载入可查看存证 {len(results)} 条（按当前登录用户权限过滤）", module="search")
        self.lbl_search_summary.setText(summary)
        if not quiet:
            self.log(f"检索完成，命中 {len(results)} 条；双击一行可自动填入解密区", module="search")

    def _on_search_double_clicked(self, index):
        row = index.row()
        if row < 0 or row >= self.tbl_search_results.rowCount():
            return
        item = self.tbl_search_results.item(row, 0)
        data = item.data(Qt.UserRole) if item else None
        if not data:
            return
        file_id = data.get("file_id") or ""
        self.edt_decrypt_file_id.setText(file_id)
        ev_no = data.get("evidence_no") or ""
        self._goto_page(3)                     # 跳到「授权解密」页，便于直接输入口令
        self.log(f"📌 从检索结果取 file_id={file_id}（ev_no={short(ev_no, 12, 6)}），请输入解密口令", module="search")

    # ------------------------------------------- 授权解密还原 → 验真闭环（P0-1 + P0-4）
    def _pick_file_id_from_current(self):
        """从验真页选中的存证（cmb_evidence）反查链上 file_id，填入解密区。"""
        ev_no = self.cmb_evidence.currentData()
        if not ev_no:
            self.log("⚠ 验真页未选中任何存证", module="decrypt")
            return
        on_chain = self.chain.query_evidence(ev_no)
        if not on_chain:
            self.log(f"⚠ 链上找不到存证 {short(ev_no, 12, 6)}", module="decrypt")
            return
        extra = on_chain["transaction"].get("extra") or ""
        file_id, _, _ = extra.partition("|")
        self.edt_decrypt_file_id.setText(file_id)
        self.log(f"📌 从链上存证 {short(ev_no, 12, 6)} 解析到 file_id={file_id}", module="decrypt")

    def on_decrypt_and_verify(self):
        file_id = self.edt_decrypt_file_id.text().strip()
        passphrase = self.edt_decrypt_passphrase.text()
        if not file_id or not passphrase:
            self.log("⚠ 请先填写 file_id 和存证口令", module="decrypt")
            return
        self.log(f"🔓 开始解密并验真闭环：file_id={file_id} ...（后台执行，不卡界面）", module="decrypt")
        self.btn_decrypt_verify.setEnabled(False)

        def _do():
            return self.svc.decrypt_and_verify(file_id, passphrase)

        def _done(result):
            self.btn_decrypt_verify.setEnabled(True)
            if not result.get("ok"):
                msg = result.get("error", "未知错误")
                self.lbl_decrypt_result.setText(f"❌ 解密失败：{msg}")
                self.lbl_decrypt_result.setStyleSheet("color:#E8463A; padding:6px;")
                self.log(f"✖ 解密失败：{msg}", module="decrypt")
                self._last_recovered = None
                self.btn_save_recovered.setEnabled(False)
                return
            # 解密成功，保存明文供后续验真
            filename = result.get("filename", file_id)
            plaintext = result.get("decrypted")
            self._last_recovered = (filename, plaintext)
            self.btn_save_recovered.setEnabled(True)
            # 展示闭环验真结论
            size = result.get("size", 0)
            local = result.get("local_digest", "")
            chain = result.get("chain_digest", "")
            verified = result.get("verified", False)
            ev_no = result.get("evidence_no", "")
            if verified:
                color = GREEN
                verdict = "🎉 验真通过"
                hint = f"解密还原成功（{size:,} 字节）+ SM3 与链上存证完全一致 → 还原的就是被存证的原始文件"
            else:
                color = RED
                verdict = "⚠ 解密成功但 SM3 不匹配"
                hint = f"解密还原成功（{size:,} 字节）但与链上 SM3 不同：密文可能被篡改，{result.get('error', '')}"
            self.lbl_decrypt_result.setText(
                f"<b>{verdict}</b> — {hint}\n"
                f"文件：{filename} ({size:,} 字节)\n"
                f"还原后 SM3 ：<span style='color:{GREEN if verified else RED};'>{local}</span>\n"
                f"链上 SM3   ：{chain}\n"
                f"链上存证号 ：{ev_no}\n"
                f"→ 可点击「保存还原明文到本地」，再到「验真溯源」页载入该文件做指纹比对"
            )
            self.lbl_decrypt_result.setStyleSheet(f"color:{color}; padding:6px;")
            self.log(f"🔓 {verdict}：{filename} 解密 {size:,} 字节，"
                     f"链上存证号 {short(ev_no, 12, 6) if ev_no else '—'}", module="decrypt")
            # 自动弹「另存为」对话框，引导保存明文
            self._save_recovered_interactive(auto=True)

        self._start_worker(_do, _done)

    def _save_recovered_interactive(self, auto: bool = False):
        """把最近一次解密成功的明文保存到本地；auto=True 表示解密成功后自动触发。"""
        if not self._last_recovered:
            self.log("⚠ 暂无已解密的明文可保存", module="decrypt")
            return
        filename, data = self._last_recovered
        suggested = filename or "recovered.bin"
        path, _ = QFileDialog.getSaveFileName(
            self, "保存还原明文", suggested, "所有文件 (*)")
        if not path:
            self.log("（已取消保存明文）" if auto else "（用户取消保存明文）", module="decrypt")
            return
        try:
            saved = self.svc.save_recovered_file(filename, data, target_path=path)
        except OSError as exc:
            self.log(f"✖ 保存明文失败：{exc}", module="decrypt")
            return
        self.log(f"✅ 明文已保存至：{saved}（{len(data):,} 字节）", module="decrypt")
        self.log("   提示：可到「验真溯源」页载入该文件，重算 SM3 与链上指纹比对", module="decrypt")
        self.lbl_decrypt_result.setText(
            self.lbl_decrypt_result.text() +
            f"\n💾 明文已保存：{saved}"
        )

    def on_save_recovered(self):
        """按钮触发：保存最近一次解密成功的明文。"""
        self._save_recovered_interactive(auto=False)

    # ------------------------------------------------ 导出证据报告（P0-3）
    def on_export_report(self):
        """验真页导出「证据报告」：带当前待验真文件做完整三重校验，输出 DOCX/PDF。"""
        ev_no = self.cmb_evidence.currentData()
        if not ev_no:
            self.log("⚠ 请先在「验真溯源」页选中一个链上存证（cmb_evidence 下拉框）", module="report")
            return
        candidate = self.tab2_file[1] if self.tab2_file else None
        if candidate is None and self.tab1_file:
            candidate = self.tab1_file[1]
        self.log(f"📄 生成证据报告：{short(ev_no, 12, 6)}（"
                 f"{'含原文件完整性校验' if candidate is not None else '仅链上核验'}）...", module="report")
        try:
            data = self.svc.proof_report(ev_no, candidate)
            block = report_export.build_proof(data)
        except Exception as exc:
            self.log(f"✖ 报告生成失败：{type(exc).__name__}: {exc}", module="report")
            dialogs.warn(self, "生成失败", f"{type(exc).__name__}: {exc}")
            return

        suggested = report_export.suggest_name(block, ev_no) + ".docx"
        path, selected = QFileDialog.getSaveFileName(
            self, "导出证据报告", suggested, "Word 文档 (*.docx);;PDF 文档 (*.pdf)")
        if not path:
            self.log("（用户取消保存）", module="report")
            return
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".docx", ".pdf"):
            ext = ".pdf" if "PDF" in (selected or "") else ".docx"
            path += ext
        try:
            report_export.export(block, path)
        except Exception as exc:
            self.log(f"✖ 导出失败：{type(exc).__name__}: {exc}", module="report")
            dialogs.warn(self, "导出失败", f"{type(exc).__name__}: {exc}")
            return
        self.log(f"✅ 证据报告已保存：{path}", module="report")
        verdict = ("通过 ✅" if data["passed"] else
                   ("部分核验 ⚠（内容一致性未核验）" if data.get("conclusion_ok") is None else "未通过 ❌"))
        self.log(f"   核验结论：{verdict}；"
                 f"完整性：{data['完整性结论']}；审计签认：{data['审计签认结论']}", module="report")


def main():
    # Windows 缩放屏下启用高分屏适配，避免界面模糊（须在 QApplication 之前设置）
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("国密区块链电子文件存证系统")
    app.setOrganizationName("contract-chain-demo")
    app.setStyle("Fusion")

    # 先登录（登录态保存在同一个 service 实例上），成功后再进入主界面
    chain = EvidenceChain(nodes=["node-A", "node-B", "node-C"],
                          required_confirmations=2)
    svc = FileEvidenceService(chain, state_path=config.STATE_PATH)
    login = LoginDialog(svc)
    if login.exec_() != QDialog.Accepted:
        return

    win = MainWindow(svc)
    win.show()
    win._apply_session(password=login._last_password)  # 加载账号密钥（首次登录自动生成，后续登录自动加载）
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
