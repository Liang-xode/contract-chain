# -*- coding: utf-8 -*-
"""
service.py —— 业务逻辑层：通用电子文件加密存证、验真溯源

定位：本服务不绑定「合同」语义，而是面向【任意电子文件】提供统一的可信存证能力：
    PDF 合同 / Word 论文 / 病历影像 / 设计图纸 / 源代码 / 报表 …… 均可加密存证。

对外提供 4 个核心用例：
    1. submit_file   文件存证（SM3 指纹 + 上传方 SM2 签名 + 原文 SM4 加密 + 上链）
    2. add_signer    多方签认（追加确认人并各自上链）
    3. verify        验真（完整性 + 签名合法性 + 链上一致性 三重校验）
    4. evidence_report 生成存证凭证

业务层只调用 crypto / blockchain 的抽象接口，不接触算法细节，便于替换实现。
"""

import time

from crypto import crypto as cc
from blockchain.chain import EvidenceChain, Transaction


def gen_evidence_no(file_digest: str, signer_fp: str, ts: float) -> str:
    """由文件指纹+签名者+时间派生唯一存证编号（SM3 前 16 位）。"""
    raw = f"{file_digest}|{signer_fp}|{ts}".encode()
    return cc.sm3_hash(raw)[:16]


class FileEvidenceService:
    def __init__(self, chain: EvidenceChain):
        self.chain = chain
        self._files = {}        # file_id -> 文件业务记录（含密文、指纹、元数据）
        self._signatures = {}   # evidence_no -> 签认记录

    # ---------- 1. 文件存证 ----------
    def submit_file(self, file_id: str, filename: str, raw_content: bytes,
                    uploader: cc.Signer, passphrase: str,
                    meta: dict = None) -> dict:
        """
        对任意电子文件做加密存证：
          - SM3 计算文件指纹（原文不上链）
          - SM4 加密原文存储（保密）
          - 上传方用 SM2 对「文件标识+指纹+时间」签名，上链存证
        返回存证凭证。
        meta 可携带文件名、类型、大小、归属单位等描述信息。
        """
        digest = cc.sm3_hash(raw_content)                      # 1) SM3 指纹
        session_key = cc.derive_sm4_key(passphrase)           # 2) 会话密钥（演示用口令派生）
        cipher = cc.sm4_encrypt(session_key, raw_content)     # 3) SM4 加密原文

        ts = time.time()
        sign_payload = f"{file_id}|{digest}|{ts}".encode()
        signature = uploader.sign(sign_payload)               # 4) 上传方 SM2 签名
        ev_no = gen_evidence_no(digest, uploader.pubkey_fingerprint, ts)

        tx = Transaction(
            evidence_no=ev_no, contract_hash=digest,
            signer_fp=uploader.pubkey_fingerprint, signature=signature,
            pubkey=uploader.public_key, ts=ts,
            extra=file_id + "|" + filename,                    # 链上附文件名标识
        )
        receipt = self.chain.submit_evidence(tx)              # 5) 存证上链

        self._files[file_id] = {
            "id": file_id, "filename": filename, "digest": digest,
            "cipher_hex": cipher.hex(), "session_key": session_key.hex(),
            "meta": meta or {}, "created_ts": ts,
        }
        self._signatures[ev_no] = {"file_id": file_id, "signer_fp": uploader.pubkey_fingerprint}
        return {"file_id": file_id, "filename": filename, "digest": digest, "receipt": receipt}

    # ---------- 2. 多方签认 ----------
    def add_signer(self, file_id: str, filename: str, raw_content: bytes,
                   signer: cc.Signer) -> dict:
        """后续确认方对（重新计算的指纹）追加签名并上链。"""
        record = self._files.get(file_id)
        if not record:
            raise ValueError("文件尚未存证，无法追加签认")
        digest = cc.sm3_hash(raw_content)
        ts = time.time()
        sign_payload = f"{file_id}|{digest}|{ts}".encode()
        signature = signer.sign(sign_payload)
        ev_no = gen_evidence_no(digest, signer.pubkey_fingerprint, ts)
        tx = Transaction(
            evidence_no=ev_no, contract_hash=digest,
            signer_fp=signer.pubkey_fingerprint, signature=signature,
            pubkey=signer.public_key, ts=ts,
            extra=file_id + "|" + filename,
        )
        receipt = self.chain.submit_evidence(tx)
        self._signatures[ev_no] = {"file_id": file_id, "signer_fp": signer.pubkey_fingerprint}
        return {"file_id": file_id, "signer": signer.pubkey_fingerprint,
                "digest": digest, "receipt": receipt}

    # ---------- 3. 验真 ----------
    def verify(self, evidence_no: str, candidate: bytes) -> dict:
        """
        三重校验：
          (a) 完整性：本地 SM3 == 链上 SM3（篡改检测）
          (b) 签名合法：链上公钥验签通过（不可否认性）
          (c) 链上存证存在且链完整（可信存证）
        """
        result = {"evidence_no": evidence_no, "passed": False, "checks": {}}

        # (c) 链上存在性
        on_chain = self.chain.query_evidence(evidence_no)
        if on_chain is None:
            result["checks"]["链上存证"] = "失败：链上无此存证记录"
            return result
        tx = on_chain["transaction"]
        result["checks"]["链上存证"] = "通过：存在，区块 #%d" % on_chain["block"]["index"]

        # (a) 完整性
        local_digest = cc.sm3_hash(candidate)
        if local_digest == tx["contract_hash"]:
            result["checks"]["完整性(SM3)"] = "通过：文件未被篡改"
        else:
            result["checks"]["完整性(SM3)"] = f"失败：哈希不匹配\n 链上: {tx['contract_hash']}\n 本地: {local_digest}"
            result["reason"] = "文件内容被修改，SM3 指纹与链上不一致"
            return result

        # (b) 签名合法
        signer = cc.Signer.from_public_key(tx["pubkey"])
        file_id = tx["extra"].split("|")[0]
        sign_payload = f"{file_id}|{tx['contract_hash']}|{tx['ts']}".encode()
        if signer.verify(tx["signature"], sign_payload):
            result["checks"]["签名(SM2)"] = f"通过：主体 {tx['signer_fp']} 签名有效"
            result["passed"] = True
        else:
            result["checks"]["签名(SM2)"] = "失败：签名无效（签名主体不可信）"
            result["reason"] = "SM2 签名验证失败，签认行为不可信"
        return result

    # ---------- 4. 授权解密还原 ----------
    def decrypt_file(self, file_id: str, passphrase: str) -> bytes:
        """
        授权解密：用正确口令派生会话密钥，SM4 解密密文，还原原始文件。
        这是 SM4 保密性的完整闭环体现 —— 原文以密文形式保密存储，
        只有掌握口令（会话密钥）的授权方才能解密查看原文。
        """
        record = self._files.get(file_id)
        if not record:
            raise ValueError("文件不存在")
        key = cc.derive_sm4_key(passphrase)
        try:
            return cc.sm4_decrypt(key, bytes.fromhex(record["cipher_hex"]))
        except (ValueError, IndexError):
            raise ValueError("口令错误：SM4 解密失败，无法还原原文（保密性生效）")

    # ---------- 5. 存证凭证 ----------
    def evidence_report(self, evidence_no: str) -> dict:
        """生成可交付的存证凭证（含链上信息与校验状态）。"""
        on_chain = self.chain.query_evidence(evidence_no)
        if on_chain is None:
            raise ValueError("存证不存在")
        tx = on_chain["transaction"]
        return {
            "存证编号": evidence_no,
            "文件指纹(SM3)": tx["contract_hash"],
            "存证主体(公钥指纹)": tx["signer_fp"],
            "签名值(SM2)": tx["signature"],
            "区块高度": on_chain["block"]["index"],
            "区块哈希": on_chain["block"]["hash"],
            "出块节点": on_chain["block"]["validator"],
            "存证时间": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tx["ts"])),
            "共识确认数": self.chain.confirmations.get(evidence_no),
        }
