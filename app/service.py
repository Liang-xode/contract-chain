# -*- coding: utf-8 -*-
"""
service.py —— 业务逻辑层：通用电子文件加密存证、验真溯源

定位：本服务不绑定「合同」语义，而是面向【任意电子文件】提供统一的可信存证能力：
    PDF 合同 / Word 论文 / 病历影像 / 设计图纸 / 源代码 / 报表 …… 均可加密存证。

对外提供 4 个核心用例（接口保持不变）：
    1. submit_file   文件存证（SM3 指纹 + 上传方 SM2 签名 + 原文 SM4 加密 + 上链）
    2. add_signer    多方签认（追加确认人并各自上链）
    3. verify        验真（完整性 + 签名合法性 + 链上一致性 三重校验）
    4. evidence_report 生成存证凭证

持久化（本次新增）：
    - 所有数据读写一律收口到 app/dao 的仓库类（DAO），业务层不写一行 SQL；
    - 落库内容仅限 指纹 / 公钥 / 签名 / 链哈希 / 语义索引，原文与会话密钥仅存内存、绝不入库；
    - 新增 登录 / 登出 / 权限归属 入口（register_user / login / logout / current_user /
      list_evidence / count_evidence / search_evidence / evidence_by_fingerprint）。

业务层只调用 crypto / blockchain / dao 的抽象接口，不接触算法与 SQL 细节。
"""

import os
import re
import time

from crypto import crypto as cc
from blockchain.chain import Block, EvidenceChain, Transaction

from app import config
from app.dao import (
    CipherStore,
    EvidenceRepository,
    LogRepository,
    SessionRepository,
    SignerRepository,
    StateStore,
    UserRepository,
    get_session_factory,
)
from app.dao.security import hash_password, verify_password

# 可查看全部存证的角色（超级管理员拥有与管理员相同的存证查看范围）
PRIVILEGED_ROLES = ("admin", "superadmin")


def gen_evidence_no(file_digest: str, signer_fp: str, ts: float) -> str:
    """由文件指纹+签名者+时间派生唯一存证编号（SM3 前 16 位）。"""
    raw = f"{file_digest}|{signer_fp}|{ts}".encode()
    return cc.sm3_hash(raw)[:16]


class FileEvidenceService:
    def __init__(self, chain: EvidenceChain, session_factory=None, state_path=None,
                 cipher_store_dir=None):
        self.chain = chain
        self._session_factory = session_factory or get_session_factory()

        # ---- 数据访问一律收口 DAO ----
        self.users = UserRepository(self._session_factory)
        self.sessions = SessionRepository(self._session_factory)
        self.evidence = EvidenceRepository(self._session_factory)
        self.signers = SignerRepository(self._session_factory)
        self.logs = LogRepository(self._session_factory)

        # 本机密文文件服务器：SM4 密文 C 以独立 .enc 文件落盘（非原文/私钥/会话密钥）
        self._cipher_store = CipherStore(cipher_store_dir)

        # 密文路径 / 盐 仅存内存、绝不入库（硬性约束：原文与私钥不入库）；
        # 其中密文路径指向 cipher_store/ 下的 .enc 文件；历史快照中的 cipher_hex 作为兼容回退。
        self._files = {}                 # file_id -> 密文元数据
        self._current_user = None        # 当前登录用户（ORM 对象）
        self._current_token = None       # 当前登录令牌

        # ---- 链状态持久化（可选）：传入 state_path 即开启，重启自动恢复历史 ----
        # 设计说明：state_path=False/None 时不落盘（单元测试默认隔离，互不影响）。
        self._state_store = StateStore(state_path) if state_path else None
        if self._state_store:
            self._load_state()

    # ---------- 1. 文件存证 ----------
    def submit_file(self, file_id: str, filename: str, raw_content: bytes,
                    uploader: cc.Signer, passphrase: str,
                    meta: dict = None) -> dict:
        """
        对任意电子文件做加密存证：
          - SM3 计算文件指纹（原文不上链）
          - 每份文件独立随机盐 + PBKDF2-HMAC-SHA256 派生 SM4 会话密钥（高强度 KDF）
          - SM4 加密原文存储（保密，密文仅内存，盐随链上 Transaction.extra 记录）
          - 上传方用 SM2 对「文件标识+指纹+时间」签名，上链存证
        返回存证凭证。
        meta 可携带文件名、类型、大小、归属单位等描述信息。
        """
        digest = cc.sm3_hash(raw_content)                      # 1) SM3 指纹
        salt = cc.random_salt(16)                              # 2) 每份文件独立随机盐
        session_key = cc.derive_sm4_key_v2(passphrase, salt)   # 3) PBKDF2 高强度 KDF
        cipher = cc.sm4_encrypt(session_key, raw_content)     # 4) SM4 加密原文

        ts = time.time()
        sign_payload = f"{file_id}|{digest}|{ts}".encode()
        signature = uploader.sign(sign_payload)               # 5) 上传方 SM2 签名
        ev_no = gen_evidence_no(digest, uploader.pubkey_fingerprint, ts)

        # Transaction.extra 扩展格式：file_id|filename|salt_hex（三段，向后兼容两段）
        tx = Transaction(
            evidence_no=ev_no, contract_hash=digest,
            signer_fp=uploader.pubkey_fingerprint, signature=signature,
            pubkey=uploader.public_key, ts=ts,
            extra=f"{file_id}|{filename}|{salt.hex()}",
        )
        receipt = self.chain.submit_evidence(tx)              # 6) 存证上链

        # 7) 密文 C 独立落盘到本机文件服务器（非原文 / 私钥 / 会话密钥）
        cipher_path = self._cipher_store.save(file_id, cipher)

        # 8) 持久化（DAO）：只存 指纹/公钥/签名/链哈希/语义索引/密文路径，不含原文与私钥
        uploader_id = self._current_user.id if self._current_user else None
        self.evidence.save_evidence(
            file_id=file_id,
            file_sha256=digest, file_name=filename,
            signer_pubkey=uploader.public_key, signature=signature,
            chain_hash=receipt["block_hash"],
            semantic_index=self._build_semantic_index(filename, digest, meta),
            uploader_id=uploader_id,
            cipher_path=cipher_path,
        )
        self.signers.register(self._signer_name(meta), uploader.public_key, uploader_id)

        # 9) 内存态仅保留密文路径 + 随机盐（会话密钥由口令 + 盐派生，不落盘）
        self._files[file_id] = {
            "id": file_id, "filename": filename, "digest": digest,
            "cipher_path": cipher_path,                          # 密文 C 的落盘路径
            "salt": salt.hex(),                                # 独立盐随文件记录
            "meta": meta or {}, "created_ts": ts, "uploader_id": uploader_id,
        }
        self._save_state()                                    # 10) 落盘链状态（重启不丢）
        self.log_entry("evidence", f"存证上链：file_id={file_id}，存证号={ev_no}")
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

        # 持久化（DAO）：登记签认记录 + 签名人
        uploader_id = self._current_user.id if self._current_user else record.get("uploader_id")
        self.evidence.save_evidence(
            file_id=file_id,
            file_sha256=digest, file_name=filename,
            signer_pubkey=signer.public_key, signature=signature,
            chain_hash=receipt["block_hash"],
            semantic_index=self._build_semantic_index(filename, digest, None),
            uploader_id=uploader_id,
        )
        self.signers.register("signer", signer.public_key, uploader_id)
        self._save_state()                                    # 落盘链状态（重启不丢）
        return {"file_id": file_id, "signer": signer.pubkey_fingerprint,
                "digest": digest, "receipt": receipt}

    # ---------- 3. 验真 ----------
    def _verify_auditor_signatures(self, file_id: str, digest: str,
                                   uploader_fp: str, uploader_ok: bool) -> dict:
        """在链上查找同一 file_id + 同一指纹的「非上传方」追加签认（审计方），并验签。

        返回：
            auditor_fingerprint: 审计方公钥指纹（无则 None）
            auditor_signed:      审计方签认是否有效
            multi_sign_ok:       上传方 + 审计方签名均有效
        """
        auditor_fp = None
        auditor_signed = False
        # 遍历链上全部存证，找同 file_id + 同指纹、不同签名人的交易
        for ev in self.list_chain_evidence():
            if ev.get("file_id") != file_id:
                continue
            if ev.get("contract_hash") != digest:
                continue
            if ev.get("signer_fp") == uploader_fp:
                continue          # 跳过上传方本人
            full = self.chain.query_evidence(ev["evidence_no"])
            if not full:
                continue
            atx = full["transaction"]
            try:
                auditor = cc.Signer.from_public_key(atx["pubkey"])
                payload = f"{file_id}|{atx['contract_hash']}|{atx['ts']}".encode()
                if auditor.verify(atx["signature"], payload):
                    auditor_fp = atx["signer_fp"]
                    auditor_signed = True
                    break          # 取第一个有效的审计方签认
                # 签认无效：记录该指纹但继续查找（可能存在多条签认）
                auditor_fp = atx["signer_fp"]
                auditor_signed = False
            except Exception:
                continue
        return {
            "auditor_fingerprint": auditor_fp,
            "auditor_signed": auditor_signed,
            "multi_sign_ok": uploader_ok and auditor_signed,
        }

    def verify(self, evidence_no: str, candidate: bytes) -> dict:
        """
        三重校验：
          (a) 完整性：本地 SM3 == 链上 SM3（篡改检测）
          (b) 签名合法：链上公钥验签通过（不可否认性）
          (c) 链上存证存在且链完整（可信存证）
        另：若本地存证库已有该指纹记录，则与链上记录交叉核对（DAO 读，不改变返回结构）。
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
            # DAO 交叉核对：本地存证库若有该指纹记录，必须与链上一致（不一致即判定存证被篡改）
            records = self.evidence.find_by_fingerprint(local_digest)
            if records and not any(
                r.signer_pubkey == tx["pubkey"] and r.signature == tx["signature"]
                for r in records
            ):
                result["checks"]["签名(SM2)"] = "失败：本地存证库与链上记录不一致（存证被篡改）"
                result["reason"] = "本地存证库与链上存证不一致"
                result["passed"] = False
        else:
            result["checks"]["签名(SM2)"] = "失败：签名无效（签名主体不可信）"
            result["reason"] = "SM2 签名验证失败，签认行为不可信"

        # (d) 审计方验证：查找同 file_id + 同指纹的非上传方追加签认并验签
        audit = self._verify_auditor_signatures(
            file_id, local_digest, tx["signer_fp"], uploader_ok=result["passed"])
        result.update(audit)
        if audit["auditor_signed"]:
            result["checks"]["审计方签名"] = (
                f"通过：审计方 {audit['auditor_fingerprint']} 签认有效")
        elif audit["auditor_fingerprint"]:
            result["checks"]["审计方签名"] = (
                f"失败：审计方 {audit['auditor_fingerprint']} 签认无效")
        else:
            result["checks"]["审计方签名"] = "未检测：暂无审计方追加签认"
        self.log_entry("verify", f"验真：存证号={evidence_no}，结果={'通过' if result['passed'] else '未通过'}")
        return result

    # ---------- 4. 授权解密还原 ----------
    def decrypt_file(self, file_id: str, passphrase: str) -> bytes:
        """
        授权解密：从本机密文文件服务器读取密文 C，用正确口令派生会话密钥，SM4 解密还原原文。
        这是 SM4 保密性的完整闭环 —— 原文以密文形式落盘（独立 .enc 文件），
        只有掌握口令的授权方才能解密查看原文。

        密文来源（兼容策略）：
          - 优先：cipher_store/<file_id>.enc 独立密文文件（新存证主路径）
          - 回退：历史 evidence_state.json 快照中的 cipher_hex（旧版内存密文）
          - 两者皆无 → 报错拒绝

        KDF 兼容：
          - 新存证（record 有 salt 字段）→ PBKDF2-HMAC-SHA256 × 200000 迭代
          - 历史存证（record 无 salt 字段）→ 旧固定盐 + SM3 派生（向后兼容）
        """
        record = self._files.get(file_id)
        if not record:
            raise ValueError("文件不存在：请先确认已存证且未重启丢失内存态")

        # ① 读取密文 C：优先独立密文文件，回退历史快照中的 cipher_hex
        try:
            cipher = self._cipher_store.load(file_id)
        except FileNotFoundError:
            cipher_hex = record.get("cipher_hex")
            if not cipher_hex:
                raise ValueError(f"密文文件缺失且无历史密文：file_id={file_id}，无法解密")
            cipher = bytes.fromhex(cipher_hex)

        # ② 派生会话密钥
        salt_hex = record.get("salt")
        if salt_hex:
            key = cc.derive_sm4_key_v2(passphrase, bytes.fromhex(salt_hex))
        else:
            key = cc.derive_sm4_key(passphrase)

        try:
            return cc.sm4_decrypt(key, cipher)
        except (ValueError, IndexError):
            raise ValueError("口令错误：SM4 解密失败，无法还原原文（保密性生效）")

    # ---------- 4-0. 明文保存（供验真） ----------
    def save_recovered_file(self, filename: str, data: bytes, target_path: str = None) -> str:
        """
        把授权解密还原后的明文保存到本地（供「验真溯源」页选中做指纹比对）。
          - target_path 不为空 → 写入用户指定路径（GUI「另存为」对话框的选择）
          - 否则 → 默认保存到 <项目根>/recovered/<filename>（文件名取自存证时的原名，保留扩展名）
        返回实际保存路径。
        安全说明：此为【授权解密后】接收方主动保存的明文，不改变存证环节「原文不落盘」的原则。
        """
        if target_path:
            path = target_path
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        else:
            recovered_dir = os.environ.get("CONTRACT_CHAIN_RECOVERED_DIR", config.RECOVERED_DIR)
            os.makedirs(recovered_dir, exist_ok=True)
            # 文件名仅保留安全字符，保留扩展名
            safe = "".join(c for c in filename if c.isalnum() or c in "._-（）() ")
            safe = safe.strip() or "recovered.bin"
            path = os.path.join(recovered_dir, safe)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # ---------- 4-1. 解密 → 验真闭环（P0-4） ----------
    def decrypt_and_verify(self, file_id: str, passphrase: str) -> dict:
        """
        一体化闭环：输入存证 file_id + 授权口令 → 解密还原原文 → 重算 SM3 →
        与链上 contract_hash 比对 → 返回验真结论。

        返回 dict 包含：
          - ok          : bool —— 解密成功
          - verified    : bool —— 还原后的 SM3 与链上一致（即"还原的就是被存证的那份"）
          - decrypted   : bytes —— 还原后的明文（ok=True 时有效）
          - local_digest: str —— 还原后重新计算的 SM3
          - chain_digest: str —— 链上存证的 contract_hash
          - error       : str —— 解密失败 / 链上查不到存证时的错误信息
          - filename    : str
          - size        : int
          - evidence_no : str —— 链上存证编号（可用于进一步 evidence_report）

        说明：此方法证明 "解密还原的明文 = 链上存证对应的原始文件" ——
        这是加密存证最核心的价值承诺：保密（只有口令持有者能解密） +
        可信（解密出来的东西就是被存证的那份，没有被篡改或替换）。
        """
        record = self._files.get(file_id)
        if not record:
            return {"ok": False, "verified": False, "error": f"文件未存证或内存态已丢失（file_id={file_id}）"}

        # ① 解密
        try:
            plaintext = self.decrypt_file(file_id, passphrase)
        except ValueError as exc:
            return {"ok": False, "verified": False,
                    "filename": record.get("filename"),
                    "error": str(exc)}

        # ② 重算 SM3
        local_digest = cc.sm3_hash(plaintext)

        # ③ 查链：file_id → 搜链上所有 transaction 的 extra 前缀，找到对应存证
        chain_tx = None
        for blk in self.chain.chain():
            for tx in blk.get("txs", []):
                extra = tx.get("extra") or ""
                if extra.startswith(file_id + "|"):
                    chain_tx = tx
                    break
            if chain_tx:
                break

        result = {
            "ok": True,
            "decrypted": plaintext,
            "size": len(plaintext),
            "filename": record.get("filename"),
            "local_digest": local_digest,
            "verified": False,
            "error": None,
        }
        if chain_tx is None:
            result["error"] = "链上找不到该 file_id 对应的存证记录"
            result["verified"] = False
            return result

        result["evidence_no"] = chain_tx["evidence_no"]
        result["chain_digest"] = chain_tx["contract_hash"]
        result["verified"] = (local_digest == chain_tx["contract_hash"])
        if not result["verified"]:
            result["error"] = "解密成功但还原后的 SM3 与链上存证不一致 —— 密文可能被篡改"
        self.log_entry("decrypt", f"解密验真：file_id={file_id}，"
                        f"验真={'通过' if result['verified'] else '未通过'}")
        return result

    # ---------- 5. 存证凭证 ----------
    def evidence_report(self, evidence_no: str) -> dict:
        """生成可交付的存证凭证（含链上信息与校验状态）。"""
        on_chain = self.chain.query_evidence(evidence_no)
        if on_chain is None:
            raise ValueError("存证不存在")
        tx = on_chain["transaction"]
        # 从本机 evidence 表取语义索引（AI 摘要），用于报告展示
        semantic_index = None
        try:
            records = self.evidence.find_by_fingerprint(tx["contract_hash"])
            if records:
                semantic_index = records[0].semantic_index
        except Exception:
            pass
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
            "语义摘要": semantic_index or "（无）",
        }

    # ======================================================================
    # 6. 用户 / 登录 / 登出（新增入口，全部经 DAO）
    # ======================================================================
    def register_user(self, username: str, password: str,
                      role: str = "user", display_name: str = None) -> dict:
        """注册：口令经 PBKDF2-HMAC-SHA256 加盐哈希后入库，绝不存明文。"""
        return self._user_dto(self.users.create_user(
            username, password, role=role, display_name=display_name))

    def login(self, username: str, password: str, ttl_seconds: int = 8 * 3600) -> dict:
        """登录：校验加盐哈希，签发本地登录令牌并缓存当前用户。"""
        user = self.users.verify_login(username, password)
        if user is None:
            raise ValueError("用户名或密码错误，或账号已被禁用")
        sess = self.sessions.create_session(user.id, ttl_seconds=ttl_seconds)
        self._current_user = user
        self._current_token = sess.token
        self.log_entry("auth", f"用户 {username} 登录成功")
        return {"token": sess.token, "expires_at": sess.expires_at.isoformat(),
                **self._user_dto(user)}

    def logout(self, token: str = None) -> bool:
        """登出：吊销登录令牌；不传 token 时吊销当前登录态。"""
        token = token or self._current_token
        if not token:
            return False
        username = self._current_user.username if self._current_user else None
        ok = self.sessions.revoke_session(token)
        if token == self._current_token:
            self._current_user = None
            self._current_token = None
        if username:
            self.log_entry("auth", f"用户 {username} 退出登录")
        return ok

    def current_user(self) -> dict:
        """当前登录用户（未登录返回 None）。"""
        return self._user_dto(self._current_user) if self._current_user else None

    def change_password(self, old_password: str, new_password: str) -> bool:
        """登录用户修改口令：先校验原密码，再以新的随机盐重新做 PBKDF2 哈希。"""
        if self._current_user is None:
            raise PermissionError("请先登录后再修改密码")
        if not new_password or len(new_password) < 6:
            raise ValueError("新密码至少 6 位")
        user = self.users.find_by_username(self._current_user.username)
        if user is None:
            raise ValueError("用户不存在")
        if not verify_password(old_password, user.password_hash, user.salt):
            raise ValueError("原密码不正确")
        password_hash, salt = hash_password(new_password)
        self.users.update_password(user.username, password_hash, salt)
        self._current_user = self.users.find_by_username(user.username)
        return True

    def set_user_status(self, username: str, status: str, actor=None) -> bool:
        """启用 / 停用账号：仅超级管理员可操作；超级管理员账号与当前登录账号受保护。"""
        user = self._actor(actor)
        if user is None or user.role != "superadmin":
            raise PermissionError("仅超级管理员可启用 / 停用账号")
        if status not in ("enabled", "disabled"):
            raise ValueError(f"不支持的状态：{status}")
        target = self.users.find_by_username(username)
        if target is None:
            raise ValueError(f"用户不存在：{username}")
        if target.role == "superadmin":
            raise ValueError("超级管理员账号不可修改状态")
        if target.id == user.id and status == "disabled":
            raise ValueError("不能停用当前登录账号")
        self.users.set_status(username, status)
        self.log_entry("user", f"账号状态变更：{username} → {status}")
        return True

    def delete_user(self, username: str, actor=None) -> dict:
        """删除账号：仅超级管理员可操作。

        删除的是账号本身；该用户的存证记录本体保留（uploader_id 置空，不可篡改），
        其登录态全部失效，签名人登记保留公钥、仅清空归属。
        """
        user = self._actor(actor)
        if user is None or user.role != "superadmin":
            raise PermissionError("仅超级管理员可删除用户")
        target = self.users.find_by_username(username)
        if target is None:
            raise ValueError(f"用户不存在：{username}")
        if target.role == "superadmin":
            raise ValueError("超级管理员账号不可删除")
        if target.id == user.id:
            raise ValueError("不能删除当前登录账号")
        if not self.users.delete_user(target.id):
            raise ValueError(f"用户不存在：{username}")
        self.log_entry("user", f"删除用户：{username}")
        return {"username": username, "id": target.id}

    def reset_password(self, username: str, new_password: str, actor=None) -> dict:
        """管理员代重置密码：仅超级管理员可操作，无需原密码；超级管理员账号受保护。

        重置后以新的随机盐重新做 PBKDF2 哈希，并吊销该用户全部登录态（迫使其重新登录）。
        """
        user = self._actor(actor)
        if user is None or user.role != "superadmin":
            raise PermissionError("仅超级管理员可重置用户密码")
        if not new_password or len(new_password) < 6:
            raise ValueError("新密码至少 6 位")
        target = self.users.find_by_username(username)
        if target is None:
            raise ValueError(f"用户不存在：{username}")
        if target.role == "superadmin":
            raise ValueError("超级管理员账号不可重置密码")
        password_hash, salt = hash_password(new_password)
        if not self.users.update_password(target.id, password_hash, salt):
            raise ValueError(f"用户不存在：{username}")
        self.sessions.revoke_user_sessions(target.id)
        self.log_entry("user", f"重置密码：{username}")
        return self._user_dto(self.users.find_by_username(username))

    def list_users(self, actor=None) -> list:
        """用户列表：超级管理员与管理员可查看（管理员仅用于中心页统计，用户管理页由导航守卫限制）。"""
        user = self._actor(actor)
        if user is None or user.role not in ("admin", "superadmin"):
            raise PermissionError("仅管理员可查看用户列表")
        return [self._user_dto(u) for u in self.users.list_all()]

    def set_user_role(self, username: str, role: str, actor=None) -> dict:
        """调整普通用户 / 管理员的角色：仅超级管理员可操作，超级管理员账号受保护。"""
        user = self._actor(actor)
        if user is None or user.role != "superadmin":
            raise PermissionError("仅超级管理员可修改用户权限")
        if role not in ("user", "admin"):
            raise ValueError(f"不支持的角色：{role}")
        target = self.users.find_by_username(username)
        if target is None:
            raise ValueError(f"用户不存在：{username}")
        if target.role == "superadmin":
            raise ValueError("超级管理员账号不可修改")
        self.users.set_role(username, role)
        self.log_entry("user", f"权限变更：{username} → {role}")
        return self._user_dto(self.users.find_by_username(username))

    # ---------- 操作日志持久化（按用户隔离） ----------
    USER_ACTION_MODULES = ("evidence", "verify", "search", "decrypt", "report")

    def log_entry(self, module: str, message: str, user_id=None) -> None:
        """统一写日志入口：用户操作日志记操作人，系统/鉴权日志记 NULL。
        失败不影响主流程。"""
        try:
            if module in self.USER_ACTION_MODULES:
                if user_id is None and self._current_user is not None:
                    user_id = self._current_user.id
            else:
                # 系统 / 鉴权 / 用户管理日志统一归为系统日志（user_id 为空）
                user_id = None
            self.logs.add(module, message, user_id=user_id)
        except Exception:
            pass

    def list_logs(self, module: str = None, limit: int = 200, actor=None) -> list:
        """按角色过滤查询日志：
        superadmin=全部；admin=本人操作 + 系统日志；user=仅本人操作日志。
        """
        user = self._actor(actor)
        role = user.role if user else None
        uid = user.id if user else None
        entries = self.logs.list_for(
            uid,
            include_system=role in PRIVILEGED_ROLES,
            include_all=(role == "superadmin"),
            module=module,
            limit=limit,
        )
        names = {}
        for e in entries:
            if e.user_id and e.user_id not in names:
                u = self.users.find_by_id(e.user_id)
                names[e.user_id] = u.username if u else f"#{e.user_id}"
        return [
            {"id": e.id, "module": e.module, "message": e.message,
             "user_id": e.user_id,
             "operator": names.get(e.user_id) or "系统",
             "created_at": e.created_at.isoformat() if e.created_at else None}
            for e in entries
        ]

    def clear_logs(self, actor=None) -> int:
        """清空日志：superadmin 清空全部；admin/user 仅清空本人操作日志。"""
        user = self._actor(actor)
        if user is None:
            raise PermissionError("未登录，无法清空日志")
        if user.role == "superadmin":
            return self.logs.delete_all()
        return self.logs.delete_by_user(user.id)

    # ---------- 权限归属查询：管理员看全部，普通用户只看自己 ----------
    def _actor(self, actor=None):
        """解析操作者：None=当前登录用户；dict=用户信息；str=登录令牌或用户名。"""
        if actor is None:
            return self._current_user
        if isinstance(actor, dict):
            return self.users.find_by_username(actor.get("username"))
        if isinstance(actor, str):
            return self.sessions.validate_token(actor) or self.users.find_by_username(actor)
        return None

    def list_evidence(self, actor=None) -> list:
        """按权限列出存证：管理员/超级管理员=全部；普通用户=自己的；未登录=匿名（无归属）存证。"""
        user = self._actor(actor)
        if user is not None and user.role in PRIVILEGED_ROLES:
            records = self.evidence.find_all()
        elif user is not None:
            records = self.evidence.find_by_user(user.id)
        else:
            records = self.evidence.find_by_user(None)
        return [self._evidence_dto(r) for r in records]

    def count_evidence(self, actor=None) -> int:
        """按权限统计存证数量。"""
        user = self._actor(actor)
        if user is not None and user.role in PRIVILEGED_ROLES:
            return self.evidence.count()
        if user is not None:
            return self.evidence.count(user.id)
        return len(self.evidence.find_by_user(None))

    def search_evidence(self, query: str, actor=None) -> list:
        """
        存证检索（P0-5 方案 B，如实降级，预留 LLM 语义扩展）。

        空检索词：返回「当前操作者可查看的存证列表」，权限逻辑与 list_evidence 一致
          （管理员 / 超级管理员=全部；普通用户=自己上传的；未登录=匿名（无归属）存证），
          并补全链上存证编号，供检索页进入时默认展示。
        非空检索词：仍在该「可查看范围」内按 file_id / 文件名 / 语义索引 / 指纹关键词过滤，
          任何用户都看不到权限范围之外的存证。

        数据来源（两路合并）：
          1) 链上存证：按 file_id / file_name / 语义索引 / 指纹 二次校验，并用 DAO 的归属映射做权限过滤；
          2) 本机 `evidence` 表中未上链的历史记录（如早期演示数据）：由 DAO semantic_search 召回后
             同样做关键词二次校验与权限过滤，避免历史存证检索不到。
        DAO 层（硬约束收口）：EvidenceRepository.semantic_search 按 semantic_index / file_name / file_id 匹配。

        返回 dict 含 evidence_no / file_id / file_name / file_sha256 / uploader_id / uploader_username。
        预留扩展点：DAO EvidenceRepository.semantic_search 可换成 PostgreSQL tsvector / MySQL FULLTEXT；
        LLM 语义增强（方案 A）通过替换 _extract_semantic_terms 接口不变。
        """
        user = self._actor(actor)
        q = (query or "").lower().strip()
        q_tokens = [t for t in re.split(r"[\s，。、；;：:,]+", q) if t]

        # 链上条目：补 evidence_no / block_index / file_id 等（同一指纹可能对应多条 tx，逐条保留）
        chain_events = self.list_chain_evidence()
        chain_hashes = {ev.get("contract_hash") for ev in chain_events}
        # 指纹 → 首条链上存证：给本机 evidence 记录补「存证编号 / 区块高度」
        chain_index = {}
        for ev in chain_events:
            hash_ = ev.get("contract_hash")
            if hash_ and hash_ not in chain_index:
                chain_index[hash_] = ev

        def uploader_name(uploader_id):
            if not uploader_id:
                return ""
            try:
                ur = self.users.find_by_id(uploader_id)
                return ur.username if ur else ""
            except Exception:
                return ""

        # 空检索：直接返回可查看范围内的全部存证（检索页进入 / 刷新时默认展示）
        if not q:
            results = []
            for dto in self.list_evidence(actor):
                ev = chain_index.get(dto.get("file_sha256")) or {}
                results.append({
                    "evidence_no": ev.get("evidence_no"),
                    "file_id": dto.get("file_id") or "",
                    "file_name": dto.get("file_name") or dto.get("file_id") or "",
                    "file_sha256": dto.get("file_sha256"),
                    "uploader_id": dto.get("uploader_id"),
                    "uploader_username": uploader_name(dto.get("uploader_id")),
                    "block_index": ev.get("block_index"),
                    "ts": ev.get("ts") or dto.get("created_at"),
                })
            return results

        # 归属 / 语义索引映射：同一指纹可能有多条历史记录，优先取「有归属、语义索引非空」的那条
        hash_to_uploader = {}
        hash_to_semantic = {}
        hash_to_file_id = {}
        for r in self.evidence.find_all():
            hash = r.file_sha256
            if hash not in hash_to_uploader or (hash_to_uploader[hash] is None and r.uploader_id is not None):
                hash_to_uploader[hash] = r.uploader_id
            if r.semantic_index and not hash_to_semantic.get(hash):
                hash_to_semantic[hash] = r.semantic_index
            if r.file_id and not hash_to_file_id.get(hash):
                hash_to_file_id[hash] = r.file_id

        results = []

        def allowed(uploader_id):
            if user is None:
                return uploader_id is None      # 未登录只能看匿名（无归属）存证
            if user.role in PRIVILEGED_ROLES:
                return True
            return uploader_id == user.id

        def hit(file_id, file_name, semantic, contract_hash):
            haystack = " ".join([
                str(file_id or "").lower(), str(file_name or "").lower(),
                str(semantic or "").lower(), str(contract_hash or "").lower(),
            ])
            # 自然语言 query 拆成关键词后 OR 匹配（LLM 关闭时的关键词兜底）
            return any(tok in haystack for tok in q_tokens)

        # 1) 链上存证：file_id / file_name / 语义索引 / 指纹 二次校验
        for ev in chain_events:
            contract_hash = ev.get("contract_hash")
            uploader_id = hash_to_uploader.get(contract_hash)
            if not allowed(uploader_id):
                continue
            file_id = ev.get("file_id") or hash_to_file_id.get(contract_hash) or ""
            file_name = ev.get("file_name") or ""
            if not hit(file_id, file_name, hash_to_semantic.get(contract_hash), contract_hash):
                continue
            results.append({
                "evidence_no": ev.get("evidence_no"),
                "file_id": file_id,
                "file_name": file_name or file_id,
                "file_sha256": contract_hash,
                "uploader_id": uploader_id,
                "uploader_username": uploader_name(uploader_id),
                "block_index": ev.get("block_index"),
                "ts": ev.get("ts"),
            })

        # 2) 本机存证库中未上链的历史记录（如早期演示数据）：同样按关键词 + 权限返回
        for r in self.evidence.semantic_search(query):
            if r.file_sha256 in chain_hashes:
                continue                        # 已由链上结果覆盖
            if not allowed(r.uploader_id):
                continue
            file_id = r.file_id or ""
            if not hit(file_id, r.file_name, r.semantic_index, r.file_sha256):
                continue
            results.append({
                "evidence_no": None,
                "file_id": file_id,
                "file_name": r.file_name or file_id,
                "file_sha256": r.file_sha256,
                "uploader_id": r.uploader_id,
                "uploader_username": uploader_name(r.uploader_id),
                "block_index": None,
                "ts": r.created_at,
            })
        return results

    def evidence_by_fingerprint(self, fingerprint: str, actor=None) -> list:
        """按指纹查询存证（验真/溯源）；结果按权限过滤。"""
        user = self._actor(actor)
        return [self._evidence_dto(r)
                for r in self._filter_owned(self.evidence.find_by_fingerprint(fingerprint), user)]

    @staticmethod
    def _filter_owned(records, user):
        if user is not None and user.role in PRIVILEGED_ROLES:
            return records
        if user is not None:
            return [r for r in records if r.uploader_id == user.id]
        return [r for r in records if r.uploader_id is None]

    # ======================================================================
    # 7. 链状态快照：落盘 + 重启恢复（重启不丢历史存证；历史文件仍可授权解密）
    # ======================================================================
    def list_chain_evidence(self) -> list:
        """返回链上全部存证（供 GUI 启动时回填历史列表）。仅用区块链公开 API。"""
        out = []
        for blk in self.chain.chain():
            for tx in blk.get("txs", []):
                extra = tx.get("extra") or ""
                # extra 格式：file_id|filename|salt_hex（三段，向后兼容旧的两段）
                parts = extra.split("|")
                file_id = parts[0] if parts else ""
                fname = parts[1] if len(parts) > 1 else file_id
                out.append({
                    "evidence_no": tx["evidence_no"],
                    "file_id": file_id,
                    "file_name": fname or file_id,
                    "block_index": blk["index"],
                    "ts": tx["ts"],
                    "contract_hash": tx["contract_hash"],
                    "signer_fp": tx["signer_fp"],
                })
        return out

    def _save_state(self):
        """把链状态与密文记录原子写入快照文件（state_path 为空时不做任何事）。"""
        if not self._state_store:
            return
        # 密文可落盘（密文非原文，且不含私钥/会话密钥）；会话密钥由口令派生，不落盘。
        files = {fid: {k: v for k, v in rec.items() if k != "session_key"}
                 for fid, rec in self._files.items()}
        self._state_store.save({"chain": self._serialize_chain(), "files": files})

    def _load_state(self):
        """启动时从快照恢复链与密文记录（就地写回传入的 chain，保持外部引用一致）。"""
        snapshot = self._state_store.load()
        if not snapshot:
            return
        if snapshot.get("chain"):
            self._restore_chain(snapshot["chain"])
        for fid, rec in (snapshot.get("files") or {}).items():
            rec.setdefault("id", fid)
            self._files[fid] = rec

    def _serialize_chain(self) -> dict:
        """序列化整条链：区块（含哈希/时间戳/nonce）+ 存证索引 + 确认数 + 节点配置。"""
        return {
            "nodes": list(self.chain.nodes),
            "required": self.chain.required,
            "confirmations": dict(self.chain.confirmations),
            "by_evidence": {k: list(v) for k, v in self.chain._by_evidence.items()},
            "blocks": [
                {"index": b.index, "prev_hash": b.prev_hash, "validator": b.validator,
                 "timestamp": b.timestamp, "nonce": b.nonce, "hash": b.hash,
                 "txs": [t.to_dict() for t in b.txs]}
                for b in self.chain._chain
            ],
        }

    def _restore_chain(self, data: dict) -> None:
        """把快照写回 self.chain 内部结构（就地恢复，不替换对象引用，兼容 GUI 共享该链）。"""
        blocks = []
        for bd in data.get("blocks", []):
            txs = [Transaction(t["evidence_no"], t["contract_hash"], t["signer_fp"],
                               t["signature"], t["pubkey"], t["ts"], t.get("extra", ""))
                   for t in bd.get("txs", [])]
            blk = Block(bd["index"], txs, bd["prev_hash"], bd["validator"])
            blk.timestamp = bd["timestamp"]     # 还原原始时间戳 / nonce / 哈希，保证链校验通过
            blk.nonce = bd["nonce"]
            blk.hash = bd["hash"]
            blocks.append(blk)
        if blocks:
            self.chain._chain = blocks
        if data.get("nodes"):
            self.chain.nodes = list(data["nodes"])
        if data.get("required"):
            self.chain.required = data["required"]
        self.chain._by_evidence = {k: tuple(v) for k, v in data.get("by_evidence", {}).items()}
        self.chain.confirmations = dict(data.get("confirmations", {}))

    # ---------- 内部小工具 ----------
    @staticmethod
    def _build_semantic_index(filename: str, digest: str, meta: dict) -> str:
        """
        组装语义索引文本（LLM 开启时生成摘要+关键词，否则走关键词分词兜底）。
        安全边界：只处理 文件名 + meta + 指纹，绝不接触原文 / 密文 / 私钥。
        存储格式：summary|||keyword1,keyword2,...（便于检索时拆分）。
        """
        semantic = FileEvidenceService.ai_semantic_index(filename, meta)
        summary = semantic.get("summary") or ""
        keywords = semantic.get("keywords") or []
        parts = [summary] + keywords + [str(filename), str(digest)]
        if meta:
            parts.extend(f"{k}:{v}" for k, v in meta.items())
        return " ".join(p for p in parts if p)

    @staticmethod
    def ai_semantic_index(filename: str, meta: dict = None) -> dict:
        """
        AI 语义索引占位接口：入参为文件名 + 元数据（绝不接触原文 / 密文 / 私钥），
        返回结构化语义索引 {"summary": str, "keywords": list[str]}。

        - LLM 开启且配置可用时：调用 LLM 生成摘要与关键词；
        - 否则：走本地关键词分词兜底（_extract_semantic_terms），不报错。
        """
        fallback_terms = FileEvidenceService._extract_semantic_terms(filename, meta)
        if not (config.LLM_ENABLED and config.LLM_API_BASE):
            return {"summary": filename, "keywords": fallback_terms}
        try:
            return FileEvidenceService._call_llm_semantic(filename, meta, fallback_terms)
        except Exception:
            # LLM 调用失败时静默降级到关键词兜底，保证主流程不中断
            return {"summary": filename, "keywords": fallback_terms}

    @staticmethod
    def _call_llm_semantic(filename: str, meta: dict, fallback_terms: list) -> dict:
        """调用 LLM 生成语义摘要与关键词（兼容 OpenAI 协议）。"""
        import json
        import urllib.request
        meta_str = "; ".join(f"{k}={v}" for k, v in (meta or {}).items()) if meta else ""
        prompt = (
            f"请为以下电子文件生成简短的中文语义摘要（≤30字）和 3-8 个检索关键词。\n"
            f"文件名：{filename}\n元数据：{meta_str}\n"
            f"仅返回 JSON：{{\"summary\": \"...\", \"keywords\": [\"...\"]}}"
        )
        payload = json.dumps({
            "model": config.LLM_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if config.LLM_API_KEY:
            headers["Authorization"] = f"Bearer {config.LLM_API_KEY}"
        req = urllib.request.Request(
            f"{config.LLM_API_BASE.rstrip('/')}/chat/completions",
            data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        content = body["choices"][0]["message"]["content"]
        # 提取 JSON 块（兼容模型返回带 ```json 包裹的情况）
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            parsed = json.loads(content[start:end + 1])
        else:
            parsed = {}
        return {
            "summary": str(parsed.get("summary") or filename),
            "keywords": [str(k) for k in (parsed.get("keywords") or fallback_terms)],
        }

    @staticmethod
    def _extract_semantic_terms(filename: str, meta: dict = None) -> list:
        """
        从文件名 + 元数据中抽取关键词（朴素分词：中英文 / 分隔符切分 + 去重）。
        这是方案 B 的核心；方案 A 时，此方法将替换为 LLM 摘要生成（保持签名不变）。

        输入边界：只接收 filename + meta，绝不接收 / 处理原文 / 密文 / 私钥。
        """
        import re
        terms = set()
        # 文件名分词：按中英文常见分隔符切割
        tokens = re.split(r"[\s_\-\.\(\)\[\]\{\}【】（）,，、/\\]+", filename.lower())
        for t in tokens:
            t = t.strip()
            # 去掉纯扩展名（pdf/docx）过短词，除非它本身就是独立语义单元
            if len(t) >= 2 or (meta and t in meta):
                terms.add(t)
        # meta 里的值如果是字符串也纳入关键词
        if meta:
            for v in meta.values():
                if isinstance(v, str) and len(v) >= 2:
                    terms.add(v)
        return sorted(terms)

    @staticmethod
    def _signer_name(meta: dict) -> str:
        if meta and meta.get("signer_name"):
            return str(meta["signer_name"])
        return "uploader"

    @staticmethod
    def _user_dto(user) -> dict:
        return {"id": user.id, "username": user.username, "role": user.role,
                "status": user.status, "display_name": user.display_name,
                "created_at": user.created_at.isoformat() if user.created_at else None}

    @staticmethod
    def _evidence_dto(record) -> dict:
        return {"id": record.id, "file_id": record.file_id,
                "file_sha256": record.file_sha256,
                "file_name": record.file_name, "signer_pubkey": record.signer_pubkey,
                "signature": record.signature, "chain_hash": record.chain_hash,
                "semantic_index": record.semantic_index,
                "uploader_id": record.uploader_id,
                "created_at": record.created_at.isoformat() if record.created_at else None}
