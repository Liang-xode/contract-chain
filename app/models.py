# -*- coding: utf-8 -*-
"""
models.py —— 持久化数据模型（SQLAlchemy ORM），共 4 张表

  users     用户 / 账号表
  sessions  登录态表（桌面端本地登录用）
  evidence  存证记录表
  signer    签名人登记表

设计原则（硬性约束）：
  - 密码只存 PBKDF2-HMAC-SHA256 加盐哈希，绝不存明文、绝不做可逆加密；
  - 原文与私钥绝不入库：evidence 只存 指纹 / 公钥 / 签名 / 链哈希 / 语义索引；
  - 存证记录不可篡改：Evidence 不提供 update / delete（由仓库层约束）。

字段命名说明：需求给出的 evidence 字段名为 file_sha256，但业务指纹实际由 SM3 计算，
此处沿用需求字段名 file_sha256 存放 SM3 指纹（值长度为 64 位 hex）。
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def _now() -> datetime:
    return datetime.now()


class User(Base):
    """用户 / 账号表。"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)          # PBKDF2-HMAC-SHA256 加盐哈希（hex）
    salt = Column(String(64), nullable=False)                    # 每用户独立随机盐（hex）
    role = Column(String(16), nullable=False, default="user")    # admin / user
    status = Column(String(16), nullable=False, default="enabled")  # enabled / disabled
    display_name = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, default=_now)
    updated_at = Column(DateTime, nullable=False, default=_now, onupdate=_now)


class LoginSession(Base):
    """登录态表（表名 sessions；类名避开 SQLAlchemy 的 Session）。

    桌面端本地登录用：登录成功后签发随机 token，登出即吊销。
    """

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=_now)
    expires_at = Column(DateTime, nullable=False)


class Evidence(Base):
    """存证记录表（只增不改不删，体现不可篡改）。"""

    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_sha256 = Column(String(64), nullable=False, index=True)   # 需求字段名；实际存放 SM3 指纹
    file_name = Column(String(255), nullable=False)
    signer_pubkey = Column(String(256), nullable=False)            # SM2 公钥（hex）
    signature = Column(String(256), nullable=False)                # SM2 签名（hex）
    chain_hash = Column(String(64), nullable=False)                # 链上区块哈希
    semantic_index = Column(Text, nullable=True)                   # AI 语义索引（可空，现为关键词索引）
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=_now)


class Signer(Base):
    """签名人登记表。"""

    __tablename__ = "signer"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False)
    pubkey = Column(String(256), unique=True, nullable=False)      # SM2 公钥（hex）
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=_now)
