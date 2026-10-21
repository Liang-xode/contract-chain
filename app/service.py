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

import time

from crypto import crypto as cc
from blockchain.chain import Block, EvidenceChain, Transaction

from app.dao import (
    EvidenceRepository,
    SessionRepository,
    SignerRepository,
    StateStore,
    UserRepository,
    get_session_factory,
)


def gen_evidence_no(file_digest: str, signer_fp: str, ts: float) -> str:
    """由文件指纹+签名者+时间派生唯一存证编号（SM3 前 16 位）。"""
    raw = f"{file_digest}|{signer_fp}|{ts}".encode()
    return cc.sm3_hash(raw)[:16]


class FileEvidenceService:
    def __init__(self, chain: EvidenceChain, session_factory=None, state_path=None):
        self.chain = chain
        self._session_factory = session_factory or get_session_factory()

        # ---- 数据访问一律收口 DAO ----
        self.users = UserRepository(self._session_factory)
        self.sessions = SessionRepository(self._session_factory)
        self.evidence = EvidenceRepository(self._session_factory)
        self.signers = SignerRepository(self._session_factory)

        # 密文与会话密钥仅存内存、绝不入库（硬性约束：原文与私钥不入库）；
        # 其中密文（非原文）为支持「重启后历史文件仍可授权解密」而写入链状态快照。
        self._files = {}                 # file_id -> 密文/元数据
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

        # 6) 持久化（DAO）：只存 指纹/公钥/签名/链哈希/语义索引，不含原文与私钥
        uploader_id = self._current_user.id if self._current_user else None
        self.evidence.save_evidence(
            file_sha256=digest, file_name=filename,
            signer_pubkey=uploader.public_key, signature=signature,
            chain_hash=receipt["block_hash"],
            semantic_index=self._semantic_index(filename, digest, meta),
            uploader_id=uploader_id,
        )
        self.signers.register(self._signer_name(meta), uploader.public_key, uploader_id)

        # 7) 密文仅存内存（不落库）
        self._files[file_id] = {
            "id": file_id, "filename": filename, "digest": digest,
            "cipher_hex": cipher.hex(), "session_key": session_key.hex(),
            "meta": meta or {}, "created_ts": ts, "uploader_id": uploader_id,
        }
        self._save_state()                                    # 8) 落盘链状态（重启不丢）
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
            file_sha256=digest, file_name=filename,
            signer_pubkey=signer.public_key, signature=signature,
            chain_hash=receipt["block_hash"],
            semantic_index=self._semantic_index(filename, digest, None),
            uploader_id=uploader_id,
        )
        self.signers.register("signer", signer.public_key, uploader_id)
        self._save_state()                                    # 落盘链状态（重启不丢）
        return {"file_id": file_id, "signer": signer.pubkey_fingerprint,
                "digest": digest, "receipt": receipt}

    # ---------- 3. 验真 ----------
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
        return result

    # ---------- 4. 授权解密还原 ----------
    def decrypt_file(self, file_id: str, passphrase: str) -> bytes:
        """
        授权解密：用正确口令派生会话密钥，SM4 解密密文，还原原始文件。
        这是 SM4 保密性的完整闭环体现 —— 原文以密文形式保密存储（仅内存、不落库），
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
        return {"token": sess.token, "expires_at": sess.expires_at.isoformat(),
                **self._user_dto(user)}

    def logout(self, token: str = None) -> bool:
        """登出：吊销登录令牌；不传 token 时吊销当前登录态。"""
        token = token or self._current_token
        if not token:
            return False
        ok = self.sessions.revoke_session(token)
        if token == self._current_token:
            self._current_user = None
            self._current_token = None
        return ok

    def current_user(self) -> dict:
        """当前登录用户（未登录返回 None）。"""
        return self._user_dto(self._current_user) if self._current_user else None

    def set_user_status(self, username: str, status: str) -> bool:
        """管理员启用 / 禁用账号。"""
        return self.users.set_status(username, status)

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
        """按权限列出存证：管理员=全部；普通用户=自己的；未登录=匿名（无归属）存证。"""
        user = self._actor(actor)
        if user is not None and user.role == "admin":
            records = self.evidence.find_all()
        elif user is not None:
            records = self.evidence.find_by_user(user.id)
        else:
            records = self.evidence.find_by_user(None)
        return [self._evidence_dto(r) for r in records]

    def count_evidence(self, actor=None) -> int:
        """按权限统计存证数量。"""
        user = self._actor(actor)
        if user is not None and user.role == "admin":
            return self.evidence.count()
        if user is not None:
            return self.evidence.count(user.id)
        return len(self.evidence.find_by_user(None))

    def search_evidence(self, query: str, actor=None) -> list:
        """语义检索（当前为关键词索引匹配，预留 AI 向量检索）；结果按权限过滤。"""
        user = self._actor(actor)
        return [self._evidence_dto(r)
                for r in self._filter_owned(self.evidence.semantic_search(query), user)]

    def evidence_by_fingerprint(self, fingerprint: str, actor=None) -> list:
        """按指纹查询存证（验真/溯源）；结果按权限过滤。"""
        user = self._actor(actor)
        return [self._evidence_dto(r)
                for r in self._filter_owned(self.evidence.find_by_fingerprint(fingerprint), user)]

    @staticmethod
    def _filter_owned(records, user):
        if user is not None and user.role == "admin":
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
                file_id, _, fname = extra.partition("|")
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
    def _semantic_index(filename: str, digest: str, meta: dict) -> str:
        """构建语义索引文本（文件名 + 指纹 + 元数据），作为 AI 语义检索的占位实现。"""
        parts = [str(filename), str(digest)]
        if meta:
            parts.extend(f"{k}:{v}" for k, v in meta.items())
        return " ".join(parts)

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
        return {"id": record.id, "file_sha256": record.file_sha256,
                "file_name": record.file_name, "signer_pubkey": record.signer_pubkey,
                "signature": record.signature, "chain_hash": record.chain_hash,
                "semantic_index": record.semantic_index,
                "uploader_id": record.uploader_id,
                "created_at": record.created_at.isoformat() if record.created_at else None}
