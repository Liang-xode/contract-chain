# -*- coding: utf-8 -*-
"""
smoke_report_export.py —— 两种报告模板 × 两种格式的端到端自检

在临时目录隔离运行，不触碰项目真实数据库 / 密文库。
验证：
  1) 存证凭证（receipt）与证据报告（proof）字段口径不同；
  2) 证据报告在"提供原文件"与"未提供原文件"时结论不同（不臆断通过）；
  3) DOCX / PDF 均能生成，且可被回读工具解析出标题与关键字段。
"""
import os
import sys
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import config, report_export  # noqa: E402
from app.dao.database import build_engine  # noqa: E402
from app.models import Base  # noqa: E402
from app.service import FileEvidenceService  # noqa: E402
from blockchain.chain import EvidenceChain  # noqa: E402
from crypto.crypto import KeyStore  # noqa: E402

PASS = "P@ssw0rd-123"
BODY = (
    "本合同由甲方示例实验室与乙方供应商签订。第一条约定标的与价款；"
    "第二条约定交付时间与验收标准；第三条明确违约责任：任何一方逾期履行，"
    "应按合同总价万分之五每日支付违约金；第四条约定争议提交甲方所在地法院。"
)


def read_docx(path):
    from docx import Document
    doc = Document(path)
    parts = [p.text for p in doc.paragraphs]
    for tbl in doc.tables:
        for row in tbl.rows:
            for cell in row.cells:
                parts.append(cell.text)
    return "\n".join(parts)


def read_pdf(path):
    from pypdf import PdfReader
    reader = PdfReader(path)
    return len(reader.pages), "\n".join((p.extract_text() or "") for p in reader.pages)


def main():
    tmp = tempfile.mkdtemp(prefix="cc_report_")
    engine = build_engine("sqlite:///" + os.path.join(tmp, "t.db").replace("\\", "/"))
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    config.SEMANTIC_VECTOR_PATH = os.path.join(tmp, "semantic_vectors.json")

    svc = FileEvidenceService(
        EvidenceChain(nodes=["a", "b", "c"], required_confirmations=2),
        session_factory=factory,
        cipher_store_dir=os.path.join(tmp, "cipher_store"),
    )
    svc.register_user("alice", PASS)
    svc.login("alice", PASS)
    signer = KeyStore(os.path.join(tmp, "keystore")).load_or_generate("alice", PASS)
    svc.submit_file("FILE-101", "采购合同_2026.docx", BODY.encode("utf-8"),
                    signer, PASS, meta={"归属单位": "示例实验室"})

    ev_no = svc.list_chain_evidence()[0]["evidence_no"]
    print("[1] 存证号 =", ev_no)

    receipt = svc.receipt_report(ev_no)
    proof_chain = svc.proof_report(ev_no)                        # 未提供原文件
    proof_full = svc.proof_report(ev_no, candidate=BODY.encode("utf-8"))  # 完整三重校验
    print("[2] 凭证编号 =", receipt["凭证编号"], "| 报告编号 =", proof_chain["报告编号"])
    print("    凭证结论 =", receipt["结论"][:40], "...")
    print("    证据(无原件) =", proof_chain["结论"][:46], "...")
    print("    证据(有原件) =", proof_full["结论"][:46], "...")
    assert proof_full["passed"] is True, "提供正确原文件时证据报告应判通过"
    assert "未核验" in proof_chain["完整性结论"], "未提供原文件时不得臆断完整性通过"
    # 未核验 ≠ 通过：缺原件时 passed 必须 False，且结论框走中性态（conclusion_ok=None）
    assert proof_chain["passed"] is False, "未提供原文件时不得判 passed=True"
    assert proof_chain["integrity_ok"] is None, "缺原件时 integrity_ok 应为 None"
    assert proof_chain["conclusion_ok"] is None, "缺原件时结论框应为中性态"
    assert "部分核验" in proof_chain["结论"], "缺原件的结论应写明「部分核验」"
    proof_bad = svc.proof_report(ev_no, candidate=BODY.encode("utf-8")[:-1] + b"X")
    assert proof_bad["passed"] is False, "篡改文件必须判未通过"
    assert proof_bad["integrity_ok"] is False, "篡改文件 integrity_ok 应为 False"
    assert proof_bad["结论"].startswith("核验未通过"), "未通过时结论应以此开头"
    assert "checks" not in receipt, "存证凭证不应携带三重校验明细"

    files = []
    for kind, data, tag in (("receipt", receipt, "凭证"), ("proof", proof_full, "证据")):
        build = report_export.build_receipt if kind == "receipt" else report_export.build_proof
        block = build(data)
        for ext in (".docx", ".pdf"):
            path = os.path.join(tmp, "%s_%s%s" % (tag, kind, ext))
            report_export.export(block, path)
            files.append((block, path))

    print("[3] 已生成 %d 个文件" % len(files))
    for block, path in files:
        name = os.path.basename(path)
        size = os.path.getsize(path)
        if path.endswith(".docx"):
            text = read_docx(path)
            assert block["title"] in text, "%s 缺少标题" % name
            assert receipt["存证编号"] in text or proof_full["存证编号"] in text, "%s 缺少存证编号" % name
            print("    %-28s %6d B  DOCX 回读 OK（%d 字符）" % (name, size, len(text)))
        else:
            pages, text = read_pdf(path)
            assert pages >= 1, "%s 无页面" % name
            print("    %-28s %6d B  PDF 回读 OK（%d 页，%d 字符）" % (name, size, pages, len(text)))

    # 两种模板必须真正不同：章节数与声明
    r_block = report_export.build_receipt(receipt)
    p_block = report_export.build_proof(proof_full)
    assert len(r_block["sections"]) < len(p_block["sections"]), "两种模板章节数应不同"
    assert not r_block["statement"] and p_block["statement"], "声明章节应只出现在证据报告"
    print("[4] 模板差异校验通过：凭证 %d 章 / 证据 %d 章" % (
        len(r_block["sections"]), len(p_block["sections"])))
    print("\n===== 报告导出自检通过 =====")
    return 0


if __name__ == "__main__":
    sys.exit(main())
