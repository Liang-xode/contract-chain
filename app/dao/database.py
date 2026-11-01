# -*- coding: utf-8 -*-
"""
database.py —— 引擎 / 会话工厂 / 自动建表

数据库访问一律收口在 app/dao/ 内，业务层与 GUI 层禁止直接写 SQL。

- build_engine(url)     构建引擎（sqlite 关闭线程检查，MySQL 启用连接池预检）
- get_engine()          全局引擎（进程内单例）
- get_session_factory() 全局 sessionmaker，首次调用时自动建表
- init_db()             创建全部表（已存在则跳过）
- reset_engine()        测试用：清空全局缓存
"""

import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app import config
from app.models import Base


def _resolve_url(url: str) -> str:
    """把相对的 sqlite URL 解析为项目根目录下的绝对路径，避免受启动目录影响。"""
    prefix = "sqlite:///"
    if url.startswith(prefix) and not url.startswith("sqlite:////"):
        path = url[len(prefix):]
        if path and not os.path.isabs(path):
            return prefix + os.path.join(config.BASE_DIR, path)
    return url


def build_engine(url: str = None):
    """按连接串构建引擎。切换数据库只需换 URL，逻辑不变。"""
    resolved = _resolve_url(url or config.DATABASE_URL)
    kwargs = {"echo": config.DATABASE_ECHO}
    if resolved.startswith("sqlite"):
        # GUI 的后台线程可能访问数据库，SQLite 需关闭线程检查
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # MySQL 等：启用连接池预检，避免连接失效
        kwargs["pool_pre_ping"] = True
    return create_engine(resolved, **kwargs)


_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def init_db():
    """创建全部表（已存在则跳过），并执行轻量级 schema 迁移（补列）。"""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _migrate_schema(engine)
    return True


def _migrate_schema(engine):
    """
    轻量级迁移：对已存在的旧表补列（不动数据，保证向前兼容）。
    当前处理 evidence.cipher_path（密文文件服务器路径）与 evidence.file_id（业务文件标识），均可空。
    """
    insp = inspect(engine)
    if "evidence" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("evidence")}
    pending = {
        "cipher_path": "ALTER TABLE evidence ADD COLUMN cipher_path VARCHAR(512)",
        "file_id": "ALTER TABLE evidence ADD COLUMN file_id VARCHAR(64)",
    }
    with engine.begin() as conn:
        for column, ddl in pending.items():
            if column not in cols:
                conn.execute(text(ddl))


def get_session_factory():
    """返回全局 sessionmaker，首次调用时自动建表。"""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
        init_db()
    return _session_factory


def reset_engine():
    """测试用：清空全局引擎与工厂缓存。"""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
