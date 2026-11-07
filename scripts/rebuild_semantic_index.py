# -*- coding: utf-8 -*-
"""

边界（重要）：
- 只更新 evidence.semantic_index 这一「派生检索字段」；
- 绝不修改 file_sha256 / signature / chain_hash / signer_pubkey 等存证本体字段，
  不破坏「存证不可篡改」的设计；
- 不改 cipher_store 密文，不接触原文/私钥；
- 运行前自动备份 evidence.db。

用法（需先设置智谱 Key）：
  set CONTRACT_CHAIN_LLM_API_KEY=你的Key
  python scripts/rebuild_semantic_index.py

同一指纹（file_sha256）只调用一次 LLM，避免重复计费。
"""
import os
import shutil
import sys
import time

# 允许从项目根目录直接运行
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import config                                        # noqa: E402
from app.dao.database import get_session_factory              # noqa: E402
from app.models import Evidence                               # noqa: E402
from app.service import FileEvidenceService                   # noqa: E402


def backup_db():
    """运行前备份 SQLite 数据库（仅 sqlite）。"""
    url = config.DATABASE_URL
    if not url.startswith("sqlite"):
        return None
    path = url[len("sqlite:///"):]
    if not os.path.isabs(path):
        path = os.path.join(config.BASE_DIR, path)
    if not os.path.exists(path):
        return None
    stamp = time.strftime("%Y%m%d_%H%M%S")
    bak = f"{path}.bak_{stamp}"
    shutil.copy2(path, bak)
    return bak


def build_index_text(filename: str, digest: str, summary: str, keywords: list) -> str:
    """组装新语义索引：summary|||kw1,kw2|||文件名|||指纹（保留文件名/指纹便于按它们检索）。"""
    kw = ",".join([k for k in keywords if k])
    parts = [summary or filename]
    if kw:
        parts.append(kw)
    parts.append(str(filename))
    parts.append(str(digest))
    return "|||".join(parts)


def main():
    if not config.LLM_ENABLED:
        print("[X] LLM_ENABLED=False，请先启用（app/config.py 或环境变量）")
        return 2
    if not (config.LLM_API_BASE and config.LLM_API_KEY):
        print("[X] 缺少 LLM_API_BASE / LLM_API_KEY，请先配置")
        return 2

    bak = backup_db()
    if bak:
        print(f"[i] 已备份数据库：{bak}")

    Session = get_session_factory()
    with Session() as s:
        rows = s.query(Evidence).order_by(Evidence.id).all()
        total = len(rows)
        print(f"[i] 共 {total} 条存证记录，开始按指纹去重调用 LLM ...")

        # 同一指纹只算一次
        cache = {}
        ok = fail = updated = 0
        for r in rows:
            digest = r.file_sha256 or ""
            filename = r.file_name or r.file_id or "unnamed"
            if digest in cache:
                summary, keywords = cache[digest]
            else:
                try:
                    fallback = FileEvidenceService._extract_semantic_terms(filename, None)
                    sem = FileEvidenceService._call_llm_semantic(filename, None, fallback)
                    summary = sem.get("summary") or filename
                    keywords = sem.get("keywords") or []
                    cache[digest] = (summary, keywords)
                    ok += 1
                    print(f"  [LLM] {filename} -> {summary} | {keywords}")
                except Exception as exc:
                    fail += 1
                    print(f"  [X] {filename} 调用失败，跳过：{type(exc).__name__}: {exc}")
                    continue

            new_index = build_index_text(filename, digest, summary, keywords)
            if r.semantic_index != new_index:
                r.semantic_index = new_index           # 仅更新派生字段
                updated += 1

        s.commit()

    print("\n===== 完成 =====")
    print(f"记录总数：{total}｜LLM 成功指纹数：{ok}｜失败：{fail}｜更新记录数：{updated}")
    if fail:
        print("[!] 存在失败项，未改动其 semantic_index（原值保留）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
