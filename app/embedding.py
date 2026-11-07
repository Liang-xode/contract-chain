# -*- coding: utf-8 -*-
"""
embedding.py —— 向量嵌入客户端（智谱 embedding-3，兼容 OpenAI /embeddings 协议）

设计约束：
- 任何异常（无 Key / 网络失败 / 额度不足）都返回 None，由上层降级为关键词检索；
- 只发送「摘要 + 关键词」这类非敏感文本，不发送原文、密文或私钥。
"""

import json
import urllib.request

from app import config


def is_available() -> bool:
    """向量检索是否可用（需同时满足开关、LLM 启用与凭据齐全）。"""
    return bool(
        getattr(config, "EMBEDDING_ENABLED", False)
        and config.LLM_ENABLED
        and config.LLM_API_BASE
        and config.LLM_API_KEY
    )


def embed(text: str, timeout: int = 20):
    """把文本映射为向量；不可用或失败时返回 None。"""
    if not is_available():
        return None
    text = (text or "").strip()
    if not text:
        return None
    url = config.LLM_API_BASE.rstrip("/") + "/embeddings"
    payload = {"model": config.EMBEDDING_MODEL, "input": text}
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config.LLM_API_KEY}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        items = data.get("data") or []
        if not items:
            return None
        vec = items[0].get("embedding")
        return [float(x) for x in vec] if vec else None
    except Exception:
        return None
