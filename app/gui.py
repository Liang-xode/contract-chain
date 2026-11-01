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
    from PyQt5.QtGui import QFont
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QDialog,
        QFileDialog,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
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

        # 页面改为「导航按钮 + 整页覆盖」：隐藏 QTabWidget 的标签栏，仅保留内容区
        self.tabs.tabBar().setVisible(False)
        self.tabs.setDocumentMode(True)
        self._nav_buttons = [self.btn_nav_sign, self.btn_nav_verify,
                             self.btn_nav_search, self.btn_nav_decrypt,
                             self.btn_nav_center, self.btn_nav_users]
        self._admin_ready = False

        self._augment_ui()                     # 代码动态创建新增控件（检索 / 解密 / 导出）
        self._bind()                           # 先有控件再绑信号
        self._reset_rows()
        self._load_history()                   # 重启后从本地快照回填历史链上存证
        self._apply_session()                  # 登录态、用户中心、权限页可见性

        self.log("系统就绪：模拟联盟链节点 node-A / node-B / node-C，共识确认数 2")
        self.log(f"审计方身份已生成，公钥指纹 {self.auditor.pubkey_fingerprint}")
        self.log("登录后将为您加载/生成专属 SM2 密钥对（本地加密存储，私钥永不入库）")
        self.log("提示：把任意文件拖入虚线框（或点击选择），自动计算 SM3 指纹")

    # ------------------------------------------------------------- 信号绑定
    def _bind(self):
        self.drop_sign.fileLoaded.connect(self.on_sign_file)
        self.drop_verify.fileLoaded.connect(self.on_verify_file)
        self.btn_sign.clicked.connect(self.on_sign)
        self.btn_countersign.clicked.connect(self.on_countersign)
        self.btn_verify.clicked.connect(self.on_verify)
        self.btn_tamper.clicked.connect(self.on_tamper)
        self.btn_forge.clicked.connect(self.on_forge)
        self.btn_clear_log.clicked.connect(self.log_box.clear)

        # 页面导航：点击按钮整页切换
        for idx, btn in enumerate(self._nav_buttons):
            btn.clicked.connect(lambda _=False, i=idx: self._goto_page(i))

        # 用户中心
        self.btn_change_pwd.clicked.connect(self._change_password)
        self.btn_logout.clicked.connect(self._logout)

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

        font = self.log_box.font()
        font.setFamily("Consolas")
        self.log_box.setFont(font)

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
        self.tbl_search_results = QTableWidget(0, 5)
        self.tbl_search_results.setHorizontalHeaderLabels(
            ["file_id", "存证号", "文件名", "上传账号", "指纹(SM3)"])
        self.tbl_search_results.horizontalHeader().setStretchLastSection(True)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_search_results.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
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
        self.btn_export_report = QPushButton("📄 导出证据报告 (.json)")
        self.btn_export_report.setStyleSheet(
            "QPushButton { background:#3E7BFA; color:#ffffff; padding:8px 16px; border-radius:4px; } "
            "QPushButton:hover { background:#21C8F6; }")
        decrypt_layout.addWidget(self.btn_export_report)

    # ------------------------------------------------------------- 日志/线程
    def log(self, msg: str):
        self.log_box.appendPlainText(f"[{now_ts()}] {msg}")
        bar = self.log_box.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _start_worker(self, fn, on_ok):
        worker = Worker(fn, self)
        worker.ok.connect(on_ok)
        worker.fail.connect(lambda msg: self.log(f"✖ 后台任务失败：{msg}"))
        self._workers.append(worker)
        worker.start()

    # ---------------------------------------------------------- 存证与签署
    def on_sign_file(self, name, data):
        self.tab1_file = (name, data)
        self.lbl_sign_digest.setText("SM3 指纹：计算中…")
        self.log(f"载入文件 [{name}]（{len(data):,} 字节），后台计算 SM3 指纹…")
        self._start_worker(lambda: cc.sm3_hash(data), self._on_sign_digest)

    def _on_sign_digest(self, digest):
        if not self.tab1_file:
            return
        name, data = self.tab1_file
        self.tab1_file = (name, data, digest)
        self.lbl_sign_digest.setText(f"SM3 指纹：{digest}")
        self.log(f"SM3 指纹计算完成：{digest}")

    def on_sign(self):
        if not self.tab1_file or len(self.tab1_file) < 3:
            self.log("⚠ 请先上传文件，并等待 SM3 指纹计算完成后再签署")
            return
        if self.uploader is None:
            self.log("⚠ 账号密钥未就绪 —— 请确认已成功登录；若密钥文件损坏请删除 ~/.xincain/keystore/ 下对应文件后重新登录")
            return
        # 每次签署弹出「存证授权口令」对话框；取消则中止，口令不足 6 位在弹窗内即时拦截
        dlg = PassphraseDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            self.log("（已取消签署：未设置存证授权口令）")
            return
        passphrase = dlg.passphrase()
        name, data, digest = self.tab1_file
        self._file_counter += 1
        file_id = f"FILE-{self._file_counter:03d}"

        self.log("―――― 开始签署（使用当前登录账号 SM2 密钥 + PBKDF2 口令加密原文）――――")
        self.log(f"① SM3 指纹（原文不上链）：{digest}")
        self.log(f"①-2 签名主体（账号公钥指纹）：{self.uploader.pubkey_fingerprint}")

        receipt = self.svc.submit_file(
            file_id, name, data, self.uploader, passphrase,
            meta={"文件名": name, "大小": f"{len(data):,} 字节"},
        )["receipt"]
        ev_no = receipt["evidence_no"]
        tx = self.chain.query_evidence(ev_no)["transaction"]

        self.log(f"② 签名载荷（file_id|指纹|时间戳）："
                 f"{file_id}|{short(tx['contract_hash'], 12, 6)}|{tx['ts']:.2f}")
        self.log(f"③ 上传方 SM2 私钥签名（r‖s，128 位 hex）：{short(tx['signature'], 24, 16)}")
        self.log(f"④ 广播至联盟链 → 共识确认 {receipt['confirmations']}/{len(self.chain.nodes)}，"
                 f"出块节点 {receipt['validator']}")
        self.log(f"⑤ 上链完成：存证号 {ev_no}，区块 #{receipt['block_index']}")

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

    def on_countersign(self):
        if self._signed_file is None:
            self.log("⚠ 尚无已签署文件，请先点击「签署并上链」")
            return
        name, data = self._signed_file
        result = self.svc.add_signer(self._last_file_id, name, data, self.auditor)
        ev_no = result["receipt"]["evidence_no"]
        self.log(f"审计方追加签认完成：主体 {result['signer']}，存证号 {ev_no}")
        self._register_evidence(ev_no, f"{name}（审计签认）")

    def _register_evidence(self, ev_no, filename, quiet=False):
        label = f"{short(ev_no, 12, 6)} ｜ {filename}"
        self.cmb_evidence.addItem(label, ev_no)
        self.cmb_evidence.setCurrentIndex(self.cmb_evidence.count() - 1)
        if not quiet:
            self.log(f"存证已加入验真列表：{label}")

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
                 "（重启不再丢失，可直接验真 / 解密）")

    # --------------------------------------------- 页面导航 / 登录态
    def _goto_page(self, index: int):
        """跳转页面：整页覆盖显示，不做多标签并列。"""
        if index == 5 and self.btn_nav_users.isHidden():
            return
        self.tabs.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        if index == 2:
            # 进入检索页默认做一次空检索，展示当前登录用户可查看的存证列表
            self.edt_search.clear()
            self.on_search(quiet=True)

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
                    f"公钥指纹 {self._account_signer.pubkey_fingerprint}）"
                )
            except ValueError as exc:
                self.log(f"⚠ 账号密钥加载失败：{exc}；存证将无法使用本账号签名")
                self._account_signer = None
                self.uploader = None
        elif self._account_signer is not None:
            self.uploader = self._account_signer
            self.lbl_uploader_id.setText(
                f"上传方公钥指纹：{self.uploader.pubkey_fingerprint}（账号 {user['username']}）")

        is_super = user["role"] == "superadmin"
        self.btn_nav_users.setVisible(is_super)
        if is_super:
            self._setup_user_admin()
            self._refresh_users()
        elif self.tabs.currentIndex() == 5:
            self._goto_page(0)

        self._clear_pwd_fields()
        self.lbl_pwd_msg.clear()
        if self.tabs.currentIndex() == 2:
            self.on_search(quiet=True)         # 登录态变化后刷新「可查看存证」列表
        if announce:
            self.log(f"当前登录用户：{user['display_name']}（{user['username']} / {role}），"
                     "本次存证将归属该账号")

    def _clear_pwd_fields(self):
        for edt in (self.edt_old_pwd, self.edt_new_pwd, self.edt_new_pwd2):
            edt.clear()

    def _set_pwd_msg(self, text, ok=True):
        self.lbl_pwd_msg.setText(text)
        self.lbl_pwd_msg.setStyleSheet(f"color:{GREEN if ok else RED};")

    def _change_password(self):
        old = self.edt_old_pwd.text()
        new = self.edt_new_pwd.text()
        confirm = self.edt_new_pwd2.text()
        if not old or not new:
            self._set_pwd_msg("请完整填写原密码与新密码", ok=False)
            return
        if new != confirm:
            self._set_pwd_msg("两次输入的新密码不一致", ok=False)
            return
        try:
            self.svc.change_password(old, new)
        except (PermissionError, ValueError) as exc:
            self._set_pwd_msg(str(exc), ok=False)
            return
        except Exception as exc:
            self._set_pwd_msg(f"修改失败：{type(exc).__name__}: {exc}", ok=False)
            return
        user = self.svc.current_user()
        self._clear_pwd_fields()
        self._set_pwd_msg("密码修改成功，下次登录请使用新密码", ok=True)
        self.log(f"账号 {user['username'] if user else ''} 修改密码成功（PBKDF2 重新加盐哈希）")

    def _logout(self):
        user = self.svc.current_user()
        if not user:
            return
        answer = QMessageBox.question(
            self, "退出登录", "退出后需要重新输入账号密码，确定继续？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.log(f"用户 {user['display_name']} 退出登录")
        self.svc.logout()
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
        answer = QMessageBox.question(
            self, "确认修改权限", f"确定将用户「{username}」设为{role_name}？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            info = self.svc.set_user_role(username, role)
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"修改失败：{exc}", ok=False)
            self.log(f"权限变更失败：{username} → {role_name}（{exc}）")
            return
        new_role = ROLE_NAMES.get(info["role"], info["role"])
        self._refresh_users()
        self._set_users_msg(f"已将「{username}」设为{new_role}", ok=True)
        self.log(f"权限变更：{username} → {new_role}")

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
        answer = QMessageBox.question(
            self, f"确认{label}", f"确定{label}账号「{username}」？{extra}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            self.svc.set_user_status(username, status)
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"{label}失败：{exc}", ok=False)
            self.log(f"账号{label}失败：{username}（{exc}）")
            return
        self._refresh_users()
        self._set_users_msg(f"已{label}账号「{username}」", ok=True)
        self.log(f"账号状态变更：{username} → {STATUS_NAMES.get(status, status)}")

    def _delete_user(self):
        """删除选中账号（二次确认；存证本体保留，归属清空）。"""
        username = self._selected_username()
        if not username:
            return
        answer = QMessageBox.warning(
            self, "确认删除用户",
            f"确定永久删除账号「{username}」？\n\n"
            "• 该账号的登录态立即失效\n"
            "• 其存证记录本体保留，仅清空归属（上传账号显示为未登录匿名存证）\n"
            "• 此操作不可撤销",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            self.svc.delete_user(username)
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"删除失败：{exc}", ok=False)
            self.log(f"删除用户失败：{username}（{exc}）")
            return
        self._refresh_users()
        self._set_users_msg(f"已删除账号「{username}」（存证记录保留）", ok=True)
        self.log(f"删除用户：{username}（账号已物理删除，存证本体保留、归属清空）")

    def _reset_user_password(self):
        """为选中账号代重置密码（无需原密码，重置后其登录态失效）。"""
        username = self._selected_username()
        if not username:
            return
        dlg = ResetPasswordDialog(username, self)
        if dlg.exec_() != QDialog.Accepted:
            self.log(f"（已取消重置密码：{username}）")
            return
        try:
            self.svc.reset_password(username, dlg.new_password())
        except (PermissionError, ValueError) as exc:
            self._set_users_msg(f"重置密码失败：{exc}", ok=False)
            self.log(f"重置密码失败：{username}（{exc}）")
            return
        self._refresh_users()
        self._set_users_msg(f"已重置账号「{username}」的密码", ok=True)
        self.log(f"重置密码：{username}（PBKDF2 重新加盐哈希，其登录态已失效）")

    def _set_users_msg(self, text, ok=True):
        self.lbl_users_msg.setText(text)
        self.lbl_users_msg.setStyleSheet(f"color:{GREEN if ok else RED};")

    # ------------------------------------------------------- 验真与攻击演示
    def on_verify_file(self, name, data):
        self.tab2_file = (name, data)
        self.lbl_verify_digest.setText("本地 SM3 指纹：计算中…")
        self.log(f"验真页载入文件 [{name}]（{len(data):,} 字节），计算 SM3 指纹…")
        self._start_worker(lambda: cc.sm3_hash(data), self._on_verify_digest)

    def _on_verify_digest(self, digest):
        self.lbl_verify_digest.setText(f"本地 SM3 指纹：{digest}")
        self.log(f"验真文件 SM3 指纹：{digest}")

    def _selected_evidence(self):
        ev_no = self.cmb_evidence.currentData()
        if not ev_no:
            self.log("⚠ 链上暂无存证记录，请先在「存证与签署」页完成签署")
        return ev_no

    def _candidate(self):
        if self.tab2_file:
            return self.tab2_file[1]
        if self.tab1_file and len(self.tab1_file) >= 3:
            self.log("（验真页未载入文件，自动使用存证页当前文件）")
            return self.tab1_file[1]
        self.log("⚠ 请先载入待验真的文件")
        return None

    def _reset_rows(self):
        for name in self.rows:
            self._set_row(name, None, "待检测")
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
        if v["passed"]:
            self.lbl_conclusion.setText("🎉 验真通过：文件完整、签名有效、存证可信")
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
        self.log(f"――― 三重验真：{short(ev_no, 12, 6)} ―――")
        result = self.svc.verify(ev_no, data)
        self._apply_verify(result)
        self.log("验真结论：" + ("通过 ✅" if result["passed"]
                                else f"未通过 ❌（{result.get('reason', '')}）"))

    def on_tamper(self):
        ev_no = self._selected_evidence()
        if not ev_no:
            return
        data = self._candidate()
        if data is None:
            return
        tampered = data[:-1] + bytes([data[-1] ^ 0xFF])
        self.log("攻击模拟：翻转文件最后 1 个字节（异或 0xFF）")
        result = self.svc.verify(ev_no, tampered)
        self._apply_verify(result)
        if not result["passed"]:
            self.log(f"攻击结果：篡改被识别 ❌ —— {result.get('reason', '')}")

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

        self.log("攻击模拟：攻击者用自己的私钥对同一载荷签名，冒充上传方")
        self.log(f"伪造者公钥指纹：{forger.pubkey_fingerprint}")
        self.log(f"用真实上传方公钥验签伪造签名 → {'通过（异常！）' if valid else '失败'}，冒充被识破")

        on_chain = self.chain.query_evidence(ev_no)
        self._set_row("链上存证", True, f"通过：存在，区块 #{on_chain['block']['index']}")
        self._set_row("完整性(SM3)", True, "通过：文件未被篡改")
        self._set_row("签名(SM2)", False, "失败：伪造签名无效（签名主体不可信）")
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
            self.log(f"✖ 检索失败：{type(exc).__name__}: {exc}")
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
        if query:
            summary = f"「{query}」命中的 {len(results)} 条存证（当前可查看范围内）"
            if not quiet:
                self.log(f"🔍 关键词检索：「{query}」（按当前登录用户权限过滤）")
        else:
            summary = f"当前显示可查看的 {len(results)} 条存证"
            if not quiet:
                self.log(f"📋 已载入可查看存证 {len(results)} 条（按当前登录用户权限过滤）")
        self.lbl_search_summary.setText(summary)
        if not quiet:
            self.log(f"检索完成，命中 {len(results)} 条；双击一行可自动填入解密区")

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
        self.log(f"📌 从检索结果取 file_id={file_id}（ev_no={short(ev_no, 12, 6)}），请输入解密口令")

    # ------------------------------------------- 授权解密还原 → 验真闭环（P0-1 + P0-4）
    def _pick_file_id_from_current(self):
        """从验真页选中的存证（cmb_evidence）反查链上 file_id，填入解密区。"""
        ev_no = self.cmb_evidence.currentData()
        if not ev_no:
            self.log("⚠ 验真页未选中任何存证")
            return
        on_chain = self.chain.query_evidence(ev_no)
        if not on_chain:
            self.log(f"⚠ 链上找不到存证 {short(ev_no, 12, 6)}")
            return
        extra = on_chain["transaction"].get("extra") or ""
        file_id, _, _ = extra.partition("|")
        self.edt_decrypt_file_id.setText(file_id)
        self.log(f"📌 从链上存证 {short(ev_no, 12, 6)} 解析到 file_id={file_id}")

    def on_decrypt_and_verify(self):
        file_id = self.edt_decrypt_file_id.text().strip()
        passphrase = self.edt_decrypt_passphrase.text()
        if not file_id or not passphrase:
            self.log("⚠ 请先填写 file_id 和存证口令")
            return
        self.log(f"🔓 开始解密并验真闭环：file_id={file_id} ...（后台执行，不卡界面）")
        self.btn_decrypt_verify.setEnabled(False)

        def _do():
            return self.svc.decrypt_and_verify(file_id, passphrase)

        def _done(result):
            self.btn_decrypt_verify.setEnabled(True)
            if not result.get("ok"):
                msg = result.get("error", "未知错误")
                self.lbl_decrypt_result.setText(f"❌ 解密失败：{msg}")
                self.lbl_decrypt_result.setStyleSheet("color:#E8463A; padding:6px;")
                self.log(f"✖ 解密失败：{msg}")
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
                     f"链上存证号 {short(ev_no, 12, 6) if ev_no else '—'}")
            # 自动弹「另存为」对话框，引导保存明文
            self._save_recovered_interactive(auto=True)

        self._start_worker(_do, _done)

    def _save_recovered_interactive(self, auto: bool = False):
        """把最近一次解密成功的明文保存到本地；auto=True 表示解密成功后自动触发。"""
        if not self._last_recovered:
            self.log("⚠ 暂无已解密的明文可保存")
            return
        filename, data = self._last_recovered
        suggested = filename or "recovered.bin"
        path, _ = QFileDialog.getSaveFileName(
            self, "保存还原明文", suggested, "所有文件 (*)")
        if not path:
            self.log("（已取消保存明文）" if auto else "（用户取消保存明文）")
            return
        try:
            saved = self.svc.save_recovered_file(filename, data, target_path=path)
        except OSError as exc:
            self.log(f"✖ 保存明文失败：{exc}")
            return
        self.log(f"✅ 明文已保存至：{saved}（{len(data):,} 字节）")
        self.log("   提示：可到「验真溯源」页载入该文件，重算 SM3 与链上指纹比对")
        self.lbl_decrypt_result.setText(
            self.lbl_decrypt_result.text() +
            f"\n💾 明文已保存：{saved}"
        )

    def on_save_recovered(self):
        """按钮触发：保存最近一次解密成功的明文。"""
        self._save_recovered_interactive(auto=False)

    # ------------------------------------------------ 导出证据报告（P0-3）
    def on_export_report(self):
        ev_no = self.cmb_evidence.currentData()
        if not ev_no:
            self.log("⚠ 请先在「验真溯源」页选中一个链上存证（cmb_evidence 下拉框）")
            return
        self.log(f"📄 生成证据报告：{short(ev_no, 12, 6)} ...")
        try:
            report = self.svc.evidence_report(ev_no)
        except ValueError as exc:
            self.log(f"✖ 报告生成失败：{exc}")
            return

        suggested = f"evidence_{ev_no[:12]}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出证据报告", suggested, "JSON 文件 (*.json);;所有文件 (*)")
        if not path:
            self.log("（用户取消保存）")
            return

        import json as _json
        try:
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(report, f, ensure_ascii=False, indent=2)
        except OSError as exc:
            self.log(f"✖ 写入文件失败：{exc}")
            return
        self.log(f"✅ 证据报告已保存：{path}")
        self.log(f"   含字段：存证编号 / 文件指纹 / 存证主体 / 签名值 / 区块高度 / 区块哈希 / 出块节点 / 存证时间 / 共识确认数")


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
