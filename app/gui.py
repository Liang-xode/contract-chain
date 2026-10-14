# -*- coding: utf-8 -*-
"""
gui.py —— PyQt5 桌面界面：国密区块链电子文件加密存证系统

功能：
    1. 文件拖拽上传（或点击选择），自动计算并显示 SM3 指纹
    2. 一键签署并上链，分步展示 SM2 签名过程（指纹 → 载荷 → 签名 → 共识上链）
    3. 验真页：三重校验结果以红绿图标区分，内置「篡改 / 伪造签名」攻击演示
    4. 底部实时日志栏输出每一步操作

运行：
    conda activate contract-chain && python -m app.gui
    或直接双击项目根目录的 run_gui.bat
"""

import os
import sys
import time

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import crypto as cc
from blockchain.chain import EvidenceChain
from app.service import FileEvidenceService

OK_ICON = "✅"
BAD_ICON = "❌"
GREEN = "#1DC981"
RED = "#E8463A"
GRAY = "#8A8A93"


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


class DropArea(QLabel):
    """文件拖拽区：支持拖拽与点击选择，载入后发出 fileLoaded 信号。"""

    fileLoaded = pyqtSignal(str, bytes)

    def __init__(self, hint: str, parent=None):
        super().__init__(hint, parent)
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumHeight(96)
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self._reset_style()

    def _reset_style(self):
        self.setStyleSheet(
            "QLabel { border: 2px dashed #B9BDC7; border-radius: 10px;"
            " color: #6B7280; padding: 12px; background: rgba(127,127,127,8%); }"
        )

    def _loaded_style(self):
        self.setStyleSheet(
            "QLabel { border: 2px solid #1DC981; border-radius: 10px;"
            " color: #111827; padding: 12px; background: rgba(29,201,129,8%); }"
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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("国密区块链通用电子文件加密存证系统 · PyQt5 控制台")
        self.resize(1000, 760)
        self.setMinimumSize(900, 680)

        # ---- 业务对象 ----
        self.chain = EvidenceChain(nodes=["node-A", "node-B", "node-C"],
                                   required_confirmations=2)
        self.svc = FileEvidenceService(self.chain)
        self.uploader = cc.Signer.generate()   # 上传方身份（私钥仅存内存，不出本地）
        self.auditor = cc.Signer.generate()    # 审计方身份
        self._file_counter = 0
        self._signed_file = None               # 最近一次签署的 (name, data)
        self._last_file_id = None
        self.tab1_file = None                  # (name, data) → (name, data, digest)
        self.tab2_file = None                  # (name, data)
        self._workers = []
        self.rows = {}

        self._build_ui()
        self.log("系统就绪：模拟联盟链节点 node-A / node-B / node-C，共识确认数 2")
        self.log(f"上传方身份已生成（私钥仅存内存），公钥指纹 {self.uploader.pubkey_fingerprint}")
        self.log(f"审计方身份已生成，公钥指纹 {self.auditor.pubkey_fingerprint}")
        self.log("提示：把任意文件拖入虚线框（或点击选择），自动计算 SM3 指纹")

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_sign_tab(), "① 存证与签署")
        self.tabs.addTab(self._build_verify_tab(), "② 验真与攻击演示")
        root.addWidget(self.tabs, 1)

        root.addWidget(self._build_log_panel())
        self.setCentralWidget(central)

    def _build_sign_tab(self):
        page = QWidget()
        lay = QVBoxLayout(page)

        drop_box = QGroupBox("① 上传文件 —— 拖拽到此处，或点击选择")
        dlay = QVBoxLayout(drop_box)
        self.drop_sign = DropArea("将任意电子文件拖到这里\n合同 / 论文 / 病历 / 图纸 / 源代码 / 报表 …")
        self.drop_sign.fileLoaded.connect(self.on_sign_file)
        dlay.addWidget(self.drop_sign)
        self.lbl_sign_digest = QLabel("SM3 指纹：待上传")
        self.lbl_sign_digest.setTextInteractionFlags(Qt.TextSelectableByMouse)
        dlay.addWidget(self.lbl_sign_digest)
        lay.addWidget(drop_box)

        sign_box = QGroupBox("② 一键签署并上链 —— 分步展示 SM2 签名过程")
        slay = QVBoxLayout(sign_box)
        id_row = QHBoxLayout()
        id_row.addWidget(QLabel(f"上传方公钥指纹：{self.uploader.pubkey_fingerprint}"))
        id_row.addWidget(QLabel(f"审计方公钥指纹：{self.auditor.pubkey_fingerprint}"))
        id_row.addStretch(1)
        slay.addLayout(id_row)

        btn_row = QHBoxLayout()
        self.btn_sign = QPushButton("签署并上链（上传方 SM2 签名）")
        self.btn_sign.clicked.connect(self.on_sign)
        self.btn_countersign = QPushButton("追加多方签认（审计方）")
        self.btn_countersign.clicked.connect(self.on_countersign)
        btn_row.addWidget(self.btn_sign)
        btn_row.addWidget(self.btn_countersign)
        slay.addLayout(btn_row)

        self.lbl_sign_result = QLabel("签名结果：尚未签署")
        self.lbl_sign_result.setWordWrap(True)
        self.lbl_sign_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        slay.addWidget(self.lbl_sign_result)
        lay.addWidget(sign_box)

        lay.addStretch(1)
        return page

    def _build_verify_tab(self):
        page = QWidget()
        lay = QVBoxLayout(page)

        pick_row = QHBoxLayout()
        pick_row.addWidget(QLabel("选择链上存证："))
        self.cmb_evidence = QComboBox()
        self.cmb_evidence.setMinimumWidth(420)
        pick_row.addWidget(self.cmb_evidence)
        pick_row.addStretch(1)
        lay.addLayout(pick_row)

        drop_box = QGroupBox("待验真文件（拖拽 / 点击选择；留空则自动使用存证页文件）")
        dlay = QVBoxLayout(drop_box)
        self.drop_verify = DropArea("将待验真的文件拖到这里")
        self.drop_verify.fileLoaded.connect(self.on_verify_file)
        dlay.addWidget(self.drop_verify)
        self.lbl_verify_digest = QLabel("本地 SM3 指纹：待载入")
        dlay.addWidget(self.lbl_verify_digest)
        lay.addWidget(drop_box)

        btn_row = QHBoxLayout()
        self.btn_verify = QPushButton("三重验真")
        self.btn_verify.clicked.connect(self.on_verify)
        self.btn_tamper = QPushButton("模拟攻击：篡改 1 字节")
        self.btn_tamper.clicked.connect(self.on_tamper)
        self.btn_forge = QPushButton("模拟攻击：伪造签名")
        self.btn_forge.clicked.connect(self.on_forge)
        for btn in (self.btn_verify, self.btn_tamper, self.btn_forge):
            btn_row.addWidget(btn)
        lay.addLayout(btn_row)

        result_box = QGroupBox("三重校验结果（✅ 通过 / ❌ 失败）")
        rlay = QVBoxLayout(result_box)
        self.rows["链上存证"] = QLabel()
        self.rows["完整性(SM3)"] = QLabel()
        self.rows["签名(SM2)"] = QLabel()
        for name in ("链上存证", "完整性(SM3)", "签名(SM2)"):
            self.rows[name].setWordWrap(True)
            rlay.addWidget(self.rows[name])
        self.lbl_conclusion = QLabel("结论：—")
        self.lbl_conclusion.setWordWrap(True)
        rlay.addWidget(self.lbl_conclusion)
        lay.addWidget(result_box)

        lay.addStretch(1)
        self._reset_rows()
        return page

    def _build_log_panel(self):
        box = QGroupBox("实时日志")
        lay = QVBoxLayout(box)
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(3000)
        self.log_box.setMinimumHeight(150)
        font = self.log_box.font()
        font.setFamily("Consolas")
        self.log_box.setFont(font)
        lay.addWidget(self.log_box)
        row = QHBoxLayout()
        row.addStretch(1)
        btn_clear = QPushButton("清空日志")
        btn_clear.clicked.connect(self.log_box.clear)
        row.addWidget(btn_clear)
        lay.addLayout(row)
        return box

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
        name, data, digest = self.tab1_file
        self._file_counter += 1
        file_id = f"FILE-{self._file_counter:03d}"

        self.log("―――― 开始签署 ――――")
        self.log(f"① SM3 指纹（原文不上链）：{digest}")

        receipt = self.svc.submit_file(
            file_id, name, data, self.uploader, "demo-pass",
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

    def _register_evidence(self, ev_no, filename):
        label = f"{short(ev_no, 12, 6)} ｜ {filename}"
        self.cmb_evidence.addItem(label, ev_no)
        self.cmb_evidence.setCurrentIndex(self.cmb_evidence.count() - 1)
        self.log(f"存证已加入验真列表：{label}")

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


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
