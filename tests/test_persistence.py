# -*- coding: utf-8 -*-
"""
tests/test_persistence.py —— 持久化层 / 登录体系验收测试

覆盖 5 条验收标准：
  1. 建表成功：users / sessions / evidence / signer 四表齐备
  2. 全流程可跑：注册 → 登录 → 上传 → 签署 → 验真 → 篡改 → 伪造 → 登出
  3. 口令安全：users.password_hash 为加盐哈希、库内无明文口令；
     evidence 无原文、无私钥；原始 DB 文件亦不含明文秘密
  4. 权限归属：管理员看全部，普通用户只看自己的存证
  5. 可切 MySQL：同一套逻辑用 mysql+pymysql 连接串构建的引擎 dialect 即为 mysql

运行： cd contract-chain-demo && python -m unittest tests.test_persistence -v
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text
from sqlalchemy.orm import sessionmaker

from crypto import crypto as cc
from blockchain.chain import EvidenceChain
from app.dao import build_engine
from app.dao.repository import (
    EvidenceRepository,
    SessionRepository,
    SignerRepository,
    UserRepository,
)
from app.models import Base
from app.service import FileEvidenceService


ADMIN_PASS = "Admin#2026"
USER_PASS = "User#2026"
ORIGINAL = "TOP-SECRET-ORIGINAL-CONTENT-中国机密原文".encode("utf-8")


class _BasePersistTest(unittest.TestCase):
    """每个测试建一个全新的临时 SQLite 库，隔离互不影响。"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="cc_persist_")
        self._db_path = os.path.join(self._tmpdir, "test_evidence.db").replace("\\", "/")
        self.engine = build_engine("sqlite:///" + self._db_path)
        Base.metadata.create_all(bind=self.engine)
        self.factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.chain = EvidenceChain()
        self.svc = FileEvidenceService(self.chain, session_factory=self.factory)

    def tearDown(self):
        try:
            self.engine.dispose()
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# ① 建表
# --------------------------------------------------------------------------- #
class TestSchema(_BasePersistTest):
    def test_four_tables_created(self):
        names = set(inspect(self.engine).get_table_names())
        self.assertTrue({"users", "sessions", "evidence", "signer"} <= names, names)

    def test_users_has_hash_and_salt_columns(self):
        cols = {c["name"] for c in inspect(self.engine).get_columns("users")}
        self.assertTrue({"password_hash", "salt", "role", "status"} <= cols, cols)
        self.assertNotIn("password", cols)  # 不存在明文口令列

    def test_evidence_columns(self):
        cols = {c["name"] for c in inspect(self.engine).get_columns("evidence")}
        self.assertTrue(
            {"file_sha256", "file_name", "signer_pubkey", "signature",
             "chain_hash", "semantic_index", "uploader_id"} <= cols, cols)


# --------------------------------------------------------------------------- #
# ② 全流程
# --------------------------------------------------------------------------- #
class TestFullLifecycle(_BasePersistTest):
    def test_register_login_upload_verify_tamper_forge_logout(self):
        # 注册 + 登录
        self.svc.register_user("admin", ADMIN_PASS, role="admin", display_name="管理员")
        logged = self.svc.login("admin", ADMIN_PASS)
        self.assertIn("token", logged)
        self.assertGreater(len(logged["token"]), 0)
        self.assertEqual(self.svc.current_user()["username"], "admin")

        # 上传 / 签署
        uploader = cc.Signer.generate()
        created = self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, uploader, "pp")
        ev_no = created["receipt"]["evidence_no"]

        # 验真通过
        v = self.svc.verify(ev_no, ORIGINAL)
        self.assertTrue(v["passed"], v)

        # 篡改：改 1 字节 -> 完整性失败
        v2 = self.svc.verify(ev_no, ORIGINAL[:-1] + b"X")
        self.assertFalse(v2["passed"])

        # 伪造：伪造者签名用真实来源公钥验签必失败
        forger = cc.Signer.generate()
        fp = cc.sm3_hash(ORIGINAL)
        payload = f"FILE-001|{fp}|{time.time()}".encode()
        self.assertFalse(uploader.verify(forger.sign(payload), payload))

        # 登出
        self.assertTrue(self.svc.logout())
        self.assertIsNone(self.svc.current_user())

    def test_login_rejects_wrong_password_and_disabled(self):
        self.svc.register_user("alice", USER_PASS)
        with self.assertRaises(ValueError):
            self.svc.login("alice", "wrong-pass")
        self.assertTrue(self.svc.set_user_status("alice", "disabled"))
        with self.assertRaises(ValueError):
            self.svc.login("alice", USER_PASS)


# --------------------------------------------------------------------------- #
# ③ 口令与原文 / 私钥安全
# --------------------------------------------------------------------------- #
class TestSecretsNotStored(_BasePersistTest):
    def test_password_is_salted_hash_not_plaintext(self):
        self.svc.register_user("alice", USER_PASS)
        with self.engine.connect() as c:
            row = c.execute(text(
                "SELECT username, password_hash, salt FROM users WHERE username='alice'"
            )).one()
        self.assertEqual(row.username, "alice")
        self.assertNotEqual(row.password_hash, USER_PASS)
        self.assertNotIn(USER_PASS, row.password_hash)
        self.assertEqual(len(row.password_hash), 64)   # 32 字节 hex
        self.assertEqual(len(row.salt), 32)            # 16 字节 hex
        # 同一口令 + 不同用户 -> 盐不同，哈希不同（杜绝彩虹表）
        self.svc.register_user("bob", USER_PASS)
        with self.engine.connect() as c:
            b = c.execute(text(
                "SELECT password_hash, salt FROM users WHERE username='bob'"
            )).one()
        self.assertNotEqual(row.salt, b.salt)
        self.assertNotEqual(row.password_hash, b.password_hash)

    def test_evidence_has_no_original_nor_private_key(self):
        uploader = cc.Signer.generate()
        self.svc.register_user("bob", USER_PASS)
        self.svc.login("bob", USER_PASS)
        self.svc.submit_file("FILE-002", "体检报告.jpg", ORIGINAL, uploader, "pp")

        rows = self.svc.evidence.find_by_user(self.svc.current_user()["id"])
        self.assertTrue(rows)
        blob = "|".join(str(getattr(r, col.name)) for r in rows for col in r.__table__.columns)
        self.assertNotIn(ORIGINAL.decode("utf-8"), blob)          # 原文绝不入库
        self.assertNotIn(uploader.private_key_hex, blob)          # 私钥绝不入库
        # 只存 指纹 / 公钥 / 签名 / 链哈希 / 语义索引
        self.assertEqual(rows[0].file_sha256, cc.sm3_hash(ORIGINAL))
        self.assertEqual(rows[0].signer_pubkey, uploader.public_key)

    def test_raw_db_file_contains_no_secret(self):
        uploader = cc.Signer.generate()
        self.svc.register_user("carol", USER_PASS)
        self.svc.login("carol", USER_PASS)
        self.svc.submit_file("FILE-003", "机密.pdf", ORIGINAL, uploader, "pp")
        self.svc.logout()

        with open(self._db_path, "rb") as f:
            raw = f.read()
        self.assertNotIn(ORIGINAL, raw)                            # 原文不以任何形式落盘
        self.assertNotIn(uploader.private_key_hex.encode(), raw)   # 私钥不以任何形式落盘


# --------------------------------------------------------------------------- #
# ④ 权限归属
# --------------------------------------------------------------------------- #
class TestOwnership(_BasePersistTest):
    def test_admin_sees_all_user_sees_own(self):
        self.svc.register_user("admin", ADMIN_PASS, role="admin")
        self.svc.register_user("alice", USER_PASS)
        self.svc.register_user("bob", USER_PASS)

        self.svc.login("alice", USER_PASS)
        self.svc.submit_file("A1", "a.pdf", b"alice file", cc.Signer.generate(), "p")
        a_id = self.svc.current_user()["id"]
        self.svc.logout()

        self.svc.login("bob", USER_PASS)
        self.svc.submit_file("B1", "b.pdf", b"bob file", cc.Signer.generate(), "p")
        b_id = self.svc.current_user()["id"]
        self.svc.logout()

        # 普通用户 alice：只看得到自己的
        self.assertEqual(self.svc.count_evidence(actor="alice"), 1)
        alice_records = self.svc.list_evidence(actor="alice")
        self.assertTrue(alice_records)
        self.assertTrue(all(r["uploader_id"] == a_id for r in alice_records))

        # 管理员：看全部
        admin_records = self.svc.list_evidence(actor="admin")
        owner_ids = {r["uploader_id"] for r in admin_records}
        self.assertIn(a_id, owner_ids)
        self.assertIn(b_id, owner_ids)
        self.assertEqual(self.svc.count_evidence(actor="admin"), 2)


# --------------------------------------------------------------------------- #
# ④-2 超级管理员：调整普通用户 / 管理员角色
# --------------------------------------------------------------------------- #
class TestSuperAdmin(_BasePersistTest):
    def test_only_superadmin_can_change_user_roles(self):
        self.svc.register_user("root", ADMIN_PASS, role="superadmin")
        self.svc.register_user("alice", USER_PASS)
        self.svc.register_user("ops", USER_PASS, role="admin")

        # 普通用户 / 管理员无权查看用户列表或改角色
        with self.assertRaises(PermissionError):
            self.svc.list_users(actor="alice")
        with self.assertRaises(PermissionError):
            self.svc.set_user_role("alice", "admin", actor="ops")

        # 超级管理员可查看列表并升 / 降角色
        users = self.svc.list_users(actor="root")
        self.assertTrue(any(u["username"] == "alice" for u in users))
        self.assertEqual(self.svc.set_user_role("alice", "admin", actor="root")["role"], "admin")
        self.assertEqual(self.svc.set_user_role("ops", "user", actor="root")["role"], "user")

        # 超级管理员账号受保护；不允许再创建第二个超级管理员
        with self.assertRaises(ValueError):
            self.svc.set_user_role("root", "user", actor="root")
        with self.assertRaises(ValueError):
            self.svc.set_user_role("alice", "superadmin", actor="root")

    def test_superadmin_sees_all_evidence(self):
        uploader = cc.Signer.generate()
        self.svc.register_user("root", ADMIN_PASS, role="superadmin")
        self.svc.register_user("alice", USER_PASS)
        self.svc.login("alice", USER_PASS)
        self.svc.submit_file("A1", "a.pdf", b"alice file", uploader, "p")
        self.svc.logout()
        self.assertEqual(self.svc.count_evidence(actor="root"), 1)


# --------------------------------------------------------------------------- #
# ④-3 用户中心：修改密码
# --------------------------------------------------------------------------- #
class TestChangePassword(_BasePersistTest):
    def test_change_password_requires_old_and_rehashes(self):
        self.svc.register_user("alice", USER_PASS)
        self.svc.login("alice", USER_PASS)

        with self.assertRaises(ValueError):
            self.svc.change_password("wrong-old", "NewPass#2026")
        with self.assertRaises(ValueError):
            self.svc.change_password(USER_PASS, "123")

        user_before = self.svc.users.find_by_username("alice")
        old_hash, old_salt = user_before.password_hash, user_before.salt

        self.assertTrue(self.svc.change_password(USER_PASS, "NewPass#2026"))
        user_after = self.svc.users.find_by_username("alice")

        # 新密码可登录，旧密码失效；哈希与随机盐均已更换且仍非明文
        self.svc.logout()
        with self.assertRaises(ValueError):
            self.svc.login("alice", USER_PASS)
        self.svc.login("alice", "NewPass#2026")
        self.assertNotEqual(old_hash, user_after.password_hash)
        self.assertNotEqual(old_salt, user_after.salt)
        self.assertNotIn("NewPass#2026", user_after.password_hash)


# --------------------------------------------------------------------------- #
# ⑤ 可切 MySQL（换连接串即可）
# --------------------------------------------------------------------------- #
class TestMySQLSwitchable(unittest.TestCase):
    def test_mysql_url_builds_mysql_dialect(self):
        url = "mysql+pymysql://root:your-password@127.0.0.1:3306/contract_chain?charset=utf8mb4"
        engine = build_engine(url)
        try:
            self.assertEqual(engine.dialect.name, "mysql")
            self.assertEqual(engine.dialect.driver, "pymysql")
        finally:
            engine.dispose()


# --------------------------------------------------------------------------- #
# 链状态持久化：模拟「存证后重启软件」，历史链上存证不丢、仍可验真/解密
# --------------------------------------------------------------------------- #
class TestChainPersistence(_BasePersistTest):
    def test_restart_keeps_history_and_decrypt(self):
        state_path = os.path.join(self._tmpdir, "evidence_state.json")

        # 第一次运行：上传并签署
        svc1 = FileEvidenceService(EvidenceChain(), session_factory=self.factory,
                                   state_path=state_path)
        uploader = cc.Signer.generate()
        ev_no = svc1.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, uploader, "pp")["receipt"]["evidence_no"]

        # 模拟重启：全新的空链 + 新服务，从快照恢复
        chain2 = EvidenceChain()
        svc2 = FileEvidenceService(chain2, session_factory=self.factory, state_path=state_path)

        self.assertEqual(chain2.height(), 1)                    # 创世 + 1 块，链已恢复
        self.assertTrue(chain2.is_chain_valid())               # 恢复后链完整未损
        self.assertIsNotNone(chain2.query_evidence(ev_no))     # 历史链上存证可见

        history = svc2.list_chain_evidence()
        self.assertIn(ev_no, [h["evidence_no"] for h in history])

        self.assertTrue(svc2.verify(ev_no, ORIGINAL)["passed"])       # 历史存证仍可验真
        self.assertEqual(svc2.decrypt_file("FILE-001", "pp"), ORIGINAL)  # 历史文件仍可授权解密

    def test_no_state_path_means_no_persistence(self):
        # 不传 state_path 时不落盘：全新服务的链保持为空（单元测试隔离）
        svc = FileEvidenceService(EvidenceChain(), session_factory=self.factory)
        self.assertEqual(svc.list_chain_evidence(), [])


# --------------------------------------------------------------------------- #
# 存证不可篡改 + DAO 收口
# --------------------------------------------------------------------------- #
class TestImmutability(_BasePersistTest):
    def test_evidence_repo_has_no_update_or_delete(self):
        for bad in ("update", "delete", "remove", "modify"):
            self.assertFalse(hasattr(EvidenceRepository, bad), bad)

    def test_signers_registered_idempotently(self):
        uploader = cc.Signer.generate()
        self.svc.submit_file("F1", "x.pdf", b"data", uploader, "p")
        self.svc.submit_file("F2", "x.pdf", b"data", uploader, "p")
        signers = SignerRepository(self.factory).find_by_user(None)
        matching = [s for s in signers if s.pubkey == uploader.public_key]
        self.assertEqual(len(matching), 1)   # 同一公钥只登记一次


if __name__ == "__main__":
    unittest.main(verbosity=2)
