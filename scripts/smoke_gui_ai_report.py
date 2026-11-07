# -*- coding: utf-8 -*-
"""
smoke_gui_ai_report.py —— GUI 侧「AI 语义可见 + 报告双模板双格式」离线自检

offscreen 模式构造主窗口，不弹窗、不联网、不碰真实数据库：
  1) 导航新增「AI 语义」，且导航按钮与页面索引严格对应；
  2) 报告页存在 DOCX / PDF 导出入口与凭证/证据类型切换；
  3) AI 状态刷新、索引列表刷新不报错。
"""
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from PyQt5.QtWidgets import QApplication  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import config  # noqa: E402
from app.dao.database import build_engine  # noqa: E402
from app.gui import MainWindow  # noqa: E402
from app.models import Base  # noqa: E402
from app.service import FileEvidenceService  # noqa: E402
from blockchain.chain import EvidenceChain  # noqa: E402


def main():
    tmp = tempfile.mkdtemp(prefix="cc_gui_")
    engine = build_engine("sqlite:///" + os.path.join(tmp, "t.db").replace("\\", "/"))
    Base.metadata.create_all(bind=engine)
    config.SEMANTIC_VECTOR_PATH = os.path.join(tmp, "semantic_vectors.json")

    svc = FileEvidenceService(
        EvidenceChain(nodes=["a", "b", "c"], required_confirmations=2),
        session_factory=sessionmaker(bind=engine, expire_on_commit=False),
        cipher_store_dir=os.path.join(tmp, "cipher_store"),
    )

    app = QApplication([])
    win = MainWindow(svc)

    n_tabs, n_nav = win.tabs.count(), len(win._nav_buttons)
    print("[1] tabs=%d nav=%d" % (n_tabs, n_nav))
    assert n_tabs == n_nav, "导航按钮数必须与页面数一致"
    assert n_tabs >= 9, "应至少 9 页（含新增 AI 语义页）"

    ai_idx = win.tabs.indexOf(win.findChild(type(win.tab_search), "tab_ai"))
    if ai_idx < 0:
        # findChild 按 objectName 找不到时，退化为按标题匹配
        ai_idx = [win.tabs.tabText(i) for i in range(n_tabs)].index("AI 语义")
    search_idx = win.tabs.indexOf(win.tab_search)
    print("[2] AI 页 index=%d（检索页 index=%d）" % (ai_idx, search_idx))
    assert ai_idx == search_idx + 1, "AI 语义页应紧跟在存证检索之后"

    for i in range(n_tabs):
        if win._nav_buttons[i] is getattr(win, "btn_nav_users", None):
            print("[3] 跳过用户管理页（未登录会弹权限提示）")
            continue
        print("    click %d -> %s" % (i, win.tabs.tabText(i)), flush=True)
        win._nav_buttons[i].click()
        assert win.tabs.currentIndex() == i, "第 %d 个导航按钮切到了错误页面" % i
    print("[3] 导航按钮与页面索引一一对应")

    names = [win.tabs.tabText(i) for i in range(n_tabs)]
    print("[4] 页面顺序：" + " / ".join(names))
    assert "AI 语义" in names

    for attr in ("btn_report_export_docx", "btn_report_export_pdf",
                 "btn_report_export_json", "cmb_report_kind", "chk_report_file"):
        assert hasattr(win, attr), "报告页缺少控件 %s" % attr
    assert win.cmb_report_kind.count() == 2
    kinds = [win.cmb_report_kind.itemData(i) for i in range(2)]
    print("[5] 报告类型：" + str(kinds))
    assert kinds == ["receipt", "proof"], "报告类型应为 存证凭证 / 证据报告 两套"

    win._refresh_ai_page()
    win._refresh_report_list()
    print("[6] AI 状态刷新 / 报告列表刷新无异常")
    print("[7] 顶栏 AI 标识：%s" % win.lbl_ai_badge.text())
    assert "AI 语义" in win.lbl_ai_badge.text()

    print("\n===== GUI 自检通过 =====")
    return 0


if __name__ == "__main__":
    sys.exit(main())
