# -*- coding: utf-8 -*-
"""
smoke_semantic_ab.py —— 路线 A（正文摘要索引）+ 路线 B（向量语义检索）端到端自检

在临时目录中隔离运行，不触碰项目真实数据库 / 密文库 / 向量库。
运行前需注入智谱 Key：
  set CONTRACT_CHAIN_LLM_API_KEY=你的Key
  python scripts/smoke_semantic_ab.py

验证点：
  1) 正文节选能进入语义索引（summary 体现正文主题，而非仅文件名）；
  2) 落库的 semantic_index 为 summary|||keywords|||类别|||文件名|||指纹 格式；
  3) 向量已写入本地向量库（semantic_vectors.json，隔离到临时目录）；
  4) 语义 query（字面不重合）能通过 vector 召回命中；
  5) 字面 query 仍通过 keyword 命中（降级路径可用）。
"""
import os
import sys
import tempfile
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import config
from app.dao.database import build_engine
from app.models import Base
from app.service import FileEvidenceService
from blockchain.chain import EvidenceChain
from crypto import crypto as cc
from crypto.crypto import KeyStore
from sqlalchemy.orm import sessionmaker

PASS = "P@ssw0rd-123"
BODY = (
    "本合同由甲方示例实验室与乙方供应商签订。第一条约定标的与价款；"
    "第二条约定交付时间与验收标准；第三条明确违约责任：任何一方逾期履行，"
    "应按合同总价万分之五每日支付违约金，并赔偿对方由此产生的实际损失；"
    "第四条约定争议解决方式为向甲方所在地人民法院起诉。"
)


def main():
    if not config.LLM_API_KEY:
        print("[X] 缺少 CONTRACT_CHAIN_LLM_API_KEY，无法测试 LLM 与向量能力")
        return 2

    tmp = tempfile.mkdtemp(prefix="cc_ab_")
    try:
        # 隔离：DB / 密文库 / 向量库全部指向临时目录
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

        # 文件名故意不含正文核心词，用于验证「正文语义」是否真正进入索引
        r = svc.submit_file("FILE-001", "scan_001.txt", BODY.encode("utf-8"),
                            signer, PASS, meta={"归属单位": "示例实验室"})
        rec = svc.evidence.find_by_fingerprint(cc.sm3_hash(BODY.encode("utf-8")))[0]
        print("[1] 存证成功，指纹 =", rec.file_sha256[:16])

        rec = svc.evidence.find_by_fingerprint(cc.sm3_hash(BODY.encode("utf-8")))[0]
        print("[2] semantic_index =", rec.semantic_index)
        assert "|||" in rec.semantic_index, "语义索引格式不符合 summary|||kw 约定"
        assert ("违约" in rec.semantic_index or "合同" in rec.semantic_index), \
            "正文语义未进入索引（仍是纯文件名兜底）"

        from app import semantic_store
        print("[3] 向量库条目数 =", semantic_store.count())
        assert semantic_store.count() >= 1, "向量未写入本地向量库"

        # 语义 query：字面与索引不重合
        q = "逾期履行要赔多少钱"
        from app import embedding
        qv = embedding.embed(q)
        raw = semantic_store.search(qv, top_k=10) if qv else []
        print(f"[4a] query 向量维度={len(qv) if qv else 0}，原始相似度：{[(k[:8], round(s,4)) for k,s in raw]}")
        hits = svc.search_evidence(q)
        print(f"[4] 语义检索「{q}」命中 {len(hits)} 条")
        for h in hits:
            print(f"    match={h.get('match')} score={h.get('score'):.4f} file={h.get('file_name')}")
        assert hits, "向量语义召回未命中"
        assert any(h.get("match") == "vector" for h in hits), "命中方式不是 vector，语义召回未生效"

        # 字面 query：关键词路径
        hits2 = svc.search_evidence("违约金")
        print(f"[5] 关键词检索「违约金」命中 {len(hits2)} 条，match={[h.get('match') for h in hits2]}")
        assert hits2, "关键词检索未命中"

        print("\n===== A+B 自检通过 =====")
        return 0
    finally:
        try:
            engine.dispose()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
