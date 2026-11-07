# -*- coding: utf-8 -*-
"""
semantic_store.py —— 本地语义向量索引（派生数据）

定位：
- 只存「语义摘要/关键词 -> 向量」的映射，键为 SM3 指纹；**不含原文、密文、私钥**；
- 纯 Python 余弦相似度，零第三方依赖（无需 numpy/faiss/chromadb），适配桌面端；
- 可随时删除重建，不属于存证本体，不参与不可篡改校验；
- 数据规模为个人/课程/竞赛量级（数百至数千条），线性扫描足够。
"""

import json
import math
import os
import threading

from app import config

_lock = threading.Lock()


def _path() -> str:
    return config.SEMANTIC_VECTOR_PATH


def _load() -> dict:
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("items"), dict):
            return data
    except Exception:
        pass
    return {"model": config.EMBEDDING_MODEL, "items": {}}


def _save(data: dict) -> None:
    path = _path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)          # 原子替换，避免写一半损坏


def put(key: str, text: str, vec: list) -> None:
    """写入/覆盖一条向量（同一指纹重复存证时覆盖，不重复占用）。"""
    if not key or not vec:
        return
    with _lock:
        data = _load()
        data["model"] = config.EMBEDDING_MODEL
        data.setdefault("items", {})[key] = {"text": (text or "")[:2000], "vec": vec}
        _save(data)


def get(key: str):
    with _lock:
        return _load().get("items", {}).get(key)


def count() -> int:
    with _lock:
        return len(_load().get("items", {}))


def cosine(a: list, b: list) -> float:
    """余弦相似度；长度不一致或空向量返回 0。"""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0 or nb <= 0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def search(query_vec: list, top_k: int = 20):
    """返回 [(指纹, 相似度)]，按相似度降序。"""
    if not query_vec:
        return []
    with _lock:
        items = _load().get("items", {})
    scored = []
    for key, item in items.items():
        score = cosine(query_vec, item.get("vec") or [])
        if score > 0:
            scored.append((key, score))
    scored.sort(key=lambda kv: kv[1], reverse=True)
    return scored[:top_k]
