# -*- coding: utf-8 -*-
"""
crypto.py —— 国密算法统一封装层（SM2 / SM3 / SM4）

对外提供统一、易于业务层调用的国密能力：
    SM3 : 计算任意数据的 256 位哈希指纹（完整性校验）
    SM2 : 数字签名 / 验签、公钥指纹、密钥对生成与私钥安全存储（身份认证 + 不可否认性）
    SM4 : 对称加解密（原始合同保密存储）

密码服务层与业务逻辑层解耦，便于后续替换算法实现或接入硬件加密卡。
"""

import os
import json

from gmssl import func, sm2, sm3, sm4
from crypto import sm2_keys


# ---------------------------------------------------------------------------
# SM3 —— 哈希指纹
# ---------------------------------------------------------------------------
def sm3_hash(data: bytes) -> str:
    """计算 data 的 SM3 哈希值，返回 64 位小写 hex。"""
    return sm3.sm3_hash(func.bytes_to_list(data))


# ---------------------------------------------------------------------------
# SM4 —— 对称加解密（ECB + PKCS7 填充）
# ---------------------------------------------------------------------------
def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("填充数据非法")
    return data[:-pad_len]


def sm4_encrypt(key: bytes, data: bytes) -> bytes:
    """SM4 加密（ECB + PKCS7）。key 必须为 16 字节。"""
    if len(key) != 16:
        raise ValueError("SM4 密钥必须为 16 字节")
    crypt = sm4.CryptSM4()
    crypt.set_key(key, sm4.SM4_ENCRYPT)
    return crypt.crypt_ecb(_pkcs7_pad(data))


def sm4_decrypt(key: bytes, cipher: bytes) -> bytes:
    """SM4 解密（ECB + PKCS7）。"""
    if len(key) != 16:
        raise ValueError("SM4 密钥必须为 16 字节")
    crypt = sm4.CryptSM4()
    crypt.set_key(key, sm4.SM4_DECRYPT)
    return _pkcs7_unpad(crypt.crypt_ecb(cipher))


def derive_sm4_key(passphrase: str) -> bytes:
    """
    由口令派生 16 字节 SM4 密钥（用于加密存储 SM2 私钥）。
    使用 SM3 哈希取前 16 字节，保持全栈国密、无外部依赖。
    说明：demo 采用口令 + 固定盐，生产环境应改用 PBKDF2/scrypt 等高强度 KDF。
    """
    salt = b"contract-chain-demo-salt-2026"
    digest = sm3_hash(passphrase.encode("utf-8") + salt)
    return bytes.fromhex(digest)[:16]


# ---------------------------------------------------------------------------
# SM2 —— 签名者（密钥对 + 签名验签 + 私钥安全存储）
# ---------------------------------------------------------------------------
class Signer:
    """一个 SM2 数字身份。私钥可加密存储于本地，签名/验签能力由 Signer 统一封装。"""

    def __init__(self, private_key_hex: str):
        self.private_key_hex = private_key_hex
        self.public_key_hex = sm2_keys.private_key_to_public_key(private_key_hex)
        self._crypt = sm2.CryptSM2(private_key=private_key_hex, public_key=self.public_key_hex)

    # ---- 身份属性 ----
    @property
    def public_key(self) -> str:
        return self.public_key_hex

    @property
    def pubkey_fingerprint(self) -> str:
        """公钥指纹：对公钥再做 SM3 取前 16 字符，便于展示与比对。"""
        return sm3_hash(bytes.fromhex(self.public_key_hex))[:16]

    # ---- 签名 / 验签 ----
    def sign(self, data: bytes) -> str:
        """对 data 做 SM2 数字签名，返回 128 位 hex（r || s）。"""
        return self._crypt.sign_with_sm3(data)

    def verify(self, signature_hex: str, data: bytes) -> bool:
        """用本签名者的公钥验签。"""
        return self._crypt.verify_with_sm3(signature_hex, data)

    # ---- 密钥安全存储 ----
    @classmethod
    def generate(cls) -> "Signer":
        return cls(func.random_hex(64))

    @classmethod
    def from_public_key(cls, public_key_hex: str) -> "Signer":
        """仅持有公钥的"验签者"（无私钥，只做验签，不参与签名）。"""
        obj = cls.__new__(cls)
        obj.public_key_hex = public_key_hex
        obj.private_key_hex = None
        obj._crypt = sm2.CryptSM2(private_key="0" * 64, public_key=public_key_hex)
        return obj

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        return {
            "name": self.name if hasattr(self, "name") else "anonymous",
            "public_key": self.public_key_hex,
            "fingerprint": self.pubkey_fingerprint,
        }


def protect_private_key(private_key_hex: str, passphrase: str) -> str:
    """用口令派生 SM4 密钥加密 SM2 私钥，返回密文 hex。私钥不出明文。"""
    key = derive_sm4_key(passphrase)
    return sm4_encrypt(key, bytes.fromhex(private_key_hex)).hex()


def unprotect_private_key(cipher_hex: str, passphrase: str) -> str:
    """解密被保护的私钥。"""
    key = derive_sm4_key(passphrase)
    return sm4_decrypt(key, bytes.fromhex(cipher_hex)).hex()


# ---------------------------------------------------------------------------
# 冒烟自测
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    s = Signer.generate()
    payload = sm3_hash(b"hello")  # 演示对哈希指纹签名
    sig = s.sign(payload.encode())
    print("SM3:", payload)
    print("公钥指纹:", s.pubkey_fingerprint)
    print("签名长度:", len(sig), "验签通过:", s.verify(sig, payload.encode()))
    print("验签伪造失败:", s.verify(sig, b"tampered"))

    # 私钥保护
    cipher = protect_private_key(s.private_key_hex, "mypass")
    recovered = unprotect_private_key(cipher, "mypass")
    print("私钥加解密保护闭环:", recovered == s.private_key_hex)
    print("SM4 对称加解密闭环:",
          sm4_decrypt(b"1234567890abcdef", sm4_encrypt(b"1234567890abcdef", b"secret text")) == b"secret text")
