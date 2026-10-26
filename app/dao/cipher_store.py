# -*- coding: utf-8 -*-
"""
cipher_store.py —— 本机「密文文件服务器」

职责：
  - 将 SM4 加密后的密文 C 以独立 .enc 文件落盘（原子写入，避免半截文件）
  - 接收方凭 file_id 读取密文 C，再配合授权口令解密还原明文

安全边界（硬性约束）：
  - 落盘的永远是【密文 C】，绝不落原文、私钥、会话密钥；
  - 文件名仅由 file_id 派生（不暴露明文内容），file_id 为业务侧生成的标识；
  - 路径穿越防护：file_id 只保留字母数字与 . _ -。

兼容策略：
  - 历史 evidence_state.json 中的 cipher_hex 仍由 service.decrypt_file 作为回退源读取；
    本模块只负责「新存证 → 独立密文文件」这条主路径。
"""
import os
import re

from app import config


class CipherStore:
    """密文文件存储：save / load / exists / path。"""

    def __init__(self, directory: str = None):
        # 支持运行时环境变量覆盖（测试隔离 / 多实例），其次构造参数，最后 config 默认值
        self.directory = (
            os.environ.get("CONTRACT_CHAIN_CIPHER_STORE_DIR")
            or directory
            or config.CIPHER_STORE_DIR
        )
        os.makedirs(self.directory, exist_ok=True)

    # ---------- 工具 ----------
    @staticmethod
    def _safe_name(file_id: str) -> str:
        """过滤 file_id，防路径穿越；为空时退回通用名。"""
        name = re.sub(r"[^A-Za-z0-9._-]", "", str(file_id or ""))
        return name or "cipher"

    def path(self, file_id: str) -> str:
        """返回该 file_id 对应密文文件的绝对路径。"""
        return os.path.join(self.directory, self._safe_name(file_id) + ".enc")

    # ---------- 读写 ----------
    def save(self, file_id: str, cipher_bytes: bytes) -> str:
        """原子写入密文文件：先写 .tmp 再 os.replace，返回落盘路径。"""
        target = self.path(file_id)
        tmp = target + ".tmp"
        with open(tmp, "wb") as f:
            f.write(cipher_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return target

    def load(self, file_id: str) -> bytes:
        """读取密文；文件缺失抛 FileNotFoundError（由上层走历史 cipher_hex 回退）。"""
        target = self.path(file_id)
        if not os.path.exists(target):
            raise FileNotFoundError(f"密文文件不存在：{target}")
        with open(target, "rb") as f:
            return f.read()

    def exists(self, file_id: str) -> bool:
        return os.path.exists(self.path(file_id))
