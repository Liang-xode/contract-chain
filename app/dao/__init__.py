# -*- coding: utf-8 -*-
"""
dao —— 数据访问层（DAO）

- database.py   引擎 / 会话工厂 / 自动建表
- security.py   口令加盐哈希（PBKDF2-HMAC-SHA256）
- repository.py 仓库类（业务层唯一的数据读写入口）

用法：
    from app.dao import get_session_factory, UserRepository
"""

from app.dao.database import build_engine, get_engine, get_session_factory, init_db, reset_engine
from app.dao.repository import (
    EvidenceRepository,
    LogRepository,
    SessionRepository,
    SignerRepository,
    UserRepository,
)
from app.dao.state_store import StateStore
from app.dao.cipher_store import CipherStore

__all__ = [
    "build_engine",
    "get_engine",
    "get_session_factory",
    "init_db",
    "reset_engine",
    "UserRepository",
    "SessionRepository",
    "EvidenceRepository",
    "LogRepository",
    "SignerRepository",
    "StateStore",
    "CipherStore",
]
