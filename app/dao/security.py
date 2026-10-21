# -*- coding: utf-8 -*-
"""
security.py —— 口令安全存储（PBKDF2-HMAC-SHA256 + 每用户独立随机盐）

硬性约束：密码绝不存明文、绝不使用可逆加密，只存加盐哈希。
"""

import hashlib
import hmac
import os

ALGORITHM = "pbkdf2_hmac_sha256"
ITERATIONS = 200_000
SALT_BYTES = 16
HASH_BYTES = 32


def new_salt() -> str:
    """生成密码学安全的随机盐（hex）。"""
    return os.urandom(SALT_BYTES).hex()


def hash_password(password: str, salt_hex: str = None):
    """返回 (password_hash_hex, salt_hex)。salt 为空时自动生成随机盐。"""
    if not isinstance(password, str) or password == "":
        raise ValueError("密码不能为空")
    salt_hex = salt_hex or new_salt()
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"),
        bytes.fromhex(salt_hex), ITERATIONS, dklen=HASH_BYTES,
    )
    return dk.hex(), salt_hex


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    """常量时间比对，校验口令与存储的加盐哈希是否匹配。"""
    if not (password_hash and salt_hex):
        return False
    try:
        candidate, _ = hash_password(password, salt_hex)
    except ValueError:
        return False
    return hmac.compare_digest(candidate, password_hash)
