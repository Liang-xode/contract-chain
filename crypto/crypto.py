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
    由口令派生 16 字节 SM4 密钥（旧版兼容路径，使用固定盐 + SM3 哈希）。
    用于：解密历史存证（无独立 salt 字段）、保护/还原 SM2 私钥（兼容性保留）。
    新存证一律使用 derive_sm4_key_v2（每份文件独立随机盐 + PBKDF2）。
    """
    salt = b"contract-chain-demo-salt-2026"
    digest = sm3_hash(passphrase.encode("utf-8") + salt)
    return bytes.fromhex(digest)[:16]


def random_salt(n: int = 16) -> bytes:
    """生成 n 字节随机盐（用于新存证 / 新密钥保护）。"""
    return os.urandom(n)


def derive_sm4_key_v2(passphrase: str, salt: bytes, iterations: int = 200000) -> bytes:
    """
    PBKDF2-HMAC-SHA256 高强度密钥派生：
      - 每份文件独立随机 salt（杜绝彩虹表 / 预计算攻击）
      - 20 万次迭代（计算延迟约 <100ms，攻击成本线性膨胀）
      - 返回 16 字节 SM4 密钥
    说明：非国密标准 KDF（PBKDF2 是 NIST/RFC 标准），但为教学演示提供
    高强度口令保护；国密等价方案是 SM2 私钥保护后的密钥协商，但
    口令场景下 PBKDF2 是行业通用选择。
    """
    import hashlib
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=16
    )


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
# 用户密钥仓库（本地加密文件系统）
# ---------------------------------------------------------------------------
KEYSTORE_DIR = os.path.join(os.path.expanduser("~"), ".xincain", "keystore")


class KeyStore:
    """
    按用户名在本地文件系统存储加密后的 SM2 私钥。
      - 路径：~/.xincain/keystore/{username}.pem（JSON）
      - 加密：每份账号密钥独立随机盐 + PBKDF2-HMAC-SHA256 × 200000
      - 明文私钥 **从不入库 / 从不写日志 / 从不传给 service 层**
      - 仅在 GUI 层登录成功时、由用户口令在本地恢复

    安全边界：
      密钥文件存在本机用户目录下，仅当攻击者拿到本机访问权 + 用户口令
      才能解密私钥 —— 与系统安全域隔离。
    """

    def __init__(self, directory: str = None):
        self._dir = directory or KEYSTORE_DIR
        os.makedirs(self._dir, exist_ok=True)

    def _path(self, username: str) -> str:
        # 防止路径穿越：只用用户名的字母数字下划线
        safe_username = "".join(c for c in username if c.isalnum() or c in "_.-")
        if not safe_username:
            raise ValueError("用户名不合法")
        return os.path.join(self._dir, f"{safe_username}.pem")

    def exists(self, username: str) -> bool:
        return os.path.isfile(self._path(username))

    def save(self, username: str, passphrase: str, signer: "Signer") -> str:
        """保存 Signer：私钥用 PBKDF2+随机盐 加密后写入文件。返回文件路径。"""
        salt = random_salt(16)
        key = derive_sm4_key_v2(passphrase, salt)
        cipher = sm4_encrypt(key, bytes.fromhex(signer.private_key_hex))
        data = {
            "version": 1,
            "username": username,
            "public_key": signer.public_key_hex,
            "salt": salt.hex(),
            "cipher": cipher.hex(),
            "fingerprint": signer.pubkey_fingerprint,
        }
        path = self._path(username)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(path, 0o600)    # POSIX: 仅本人可读写
        except (AttributeError, OSError):
            pass                       # Windows 忽略 chmod
        return path

    def load(self, username: str, passphrase: str) -> "Signer":
        """从本地加载 Signer：用口令 + 随机盐 PBKDF2 恢复私钥。"""
        path = self._path(username)
        if not os.path.isfile(path):
            raise ValueError(f"账号 {username} 无本地密钥文件")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        salt = bytes.fromhex(data["salt"])
        key = derive_sm4_key_v2(passphrase, salt)
        try:
            private_hex = sm4_decrypt(key, bytes.fromhex(data["cipher"])).hex()
        except (ValueError, IndexError):
            raise ValueError("登录口令错误：无法解密本地密钥文件")
        signer = Signer(private_hex)
        # 完整性校验：文件里存的公钥指纹必须和恢复出来的一致
        if signer.pubkey_fingerprint != data.get("fingerprint"):
            raise ValueError("密钥文件完整性校验失败（公钥指纹不匹配）")
        return signer

    def load_or_generate(self, username: str, passphrase: str) -> "Signer":
        """首次登录自动生成新密钥对并加密存储；后续登录则加载已有密钥。"""
        if self.exists(username):
            return self.load(username, passphrase)
        signer = Signer.generate()
        self.save(username, passphrase, signer)
        return signer


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
