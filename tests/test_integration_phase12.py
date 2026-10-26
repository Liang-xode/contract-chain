# -*- coding: utf-8 -*-
"""Phase 1+2+3 集成验收：PBKDF2 KDF + 账号密钥绑定 + 关键词检索 + 解密验真闭环。"""
import os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import sessionmaker
from crypto import crypto as cc
from crypto.crypto import KeyStore
from blockchain.chain import EvidenceChain
from app.dao import build_engine
from app.models import Base
from app.service import FileEvidenceService

ORIGINAL = "机密采购合同 · TOP-SECRET-中国原文 content".encode("utf-8")
ORIGINAL2 = "年度财务报表 · finance report 2026".encode("utf-8")
PASS = "StrongPass#2026"
WRONG_PASS = "wrong-pass"


class Phase12Test(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="cc_ph12_")
        self._keystore_dir = os.path.join(self._tmpdir, "keystore")
        os.makedirs(self._keystore_dir)
        # 隔离密文文件服务器，避免污染项目根目录
        os.environ["CONTRACT_CHAIN_CIPHER_STORE_DIR"] = os.path.join(self._tmpdir, "cipher_store")
        os.environ["CONTRACT_CHAIN_RECOVERED_DIR"] = os.path.join(self._tmpdir, "recovered")
        self.engine = build_engine("sqlite:///" + os.path.join(self._tmpdir, "t.db").replace("\\", "/"))
        Base.metadata.create_all(bind=self.engine)
        self.factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.svc = FileEvidenceService(EvidenceChain(nodes=["a","b","c"], required_confirmations=2),
                                       session_factory=self.factory)

    def tearDown(self):
        try: self.engine.dispose()
        except: pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ----------------------- P1-6 KeyStore ----------------------- #
    def test_keystore_first_login_generates_then_loads(self):
        store = KeyStore(self._keystore_dir)
        s1 = store.load_or_generate("alice", PASS)
        self.assertTrue(os.path.isfile(os.path.join(self._keystore_dir, "alice.pem")))
        # 二次加载应当是同一个 Signer（公私钥相同）
        s2 = store.load_or_generate("alice", PASS)
        self.assertEqual(s1.private_key_hex, s2.private_key_hex)
        self.assertEqual(s1.pubkey_fingerprint, s2.pubkey_fingerprint)

    def test_keystore_wrong_password_rejected(self):
        store = KeyStore(self._keystore_dir)
        store.load_or_generate("alice", PASS)
        with self.assertRaises(ValueError):
            store.load("alice", WRONG_PASS)

    # ---------------- P2-7 PBKDF2 新 KDF ---------------- #
    def test_submit_file_uses_per_file_salt_and_pbkdf2(self):
        self.svc.register_user("alice", PASS)
        self.svc.login("alice", PASS)
        store = KeyStore(self._keystore_dir)
        signer = store.load_or_generate("alice", PASS)
        r = self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, signer, PASS,
                                 meta={"文件名": "采购合同.pdf", "大小": len(ORIGINAL)})
        # _files 里应带独立 salt
        rec = self.svc._files["FILE-001"]
        self.assertIn("salt", rec)
        self.assertEqual(len(rec["salt"]), 32)   # 16 字节 hex
        self.assertNotIn("session_key", rec)    # 会话密钥不落盘

    def test_decrypt_and_verify_new_path_succeeds(self):
        self.svc.register_user("alice", PASS)
        self.svc.login("alice", PASS)
        store = KeyStore(self._keystore_dir)
        signer = store.load_or_generate("alice", PASS)
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, signer, PASS)
        v = self.svc.decrypt_and_verify("FILE-001", PASS)
        self.assertTrue(v["ok"], v)
        self.assertTrue(v["verified"], v)
        self.assertEqual(v["decrypted"], ORIGINAL)
        self.assertEqual(v["local_digest"], v["chain_digest"])
        self.assertIsNotNone(v.get("evidence_no"))
        self.assertEqual(v["size"], len(ORIGINAL))

    def test_decrypt_and_verify_wrong_password_rejected(self):
        self.svc.register_user("alice", PASS)
        self.svc.login("alice", PASS)
        store = KeyStore(self._keystore_dir)
        signer = store.load_or_generate("alice", PASS)
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, signer, PASS)
        v = self.svc.decrypt_and_verify("FILE-001", WRONG_PASS)
        self.assertFalse(v["ok"])
        self.assertFalse(v["verified"])
        self.assertIn("口令错误", v.get("error", ""))

    # ---------------- P0-5 关键词检索 + 权限 ---------------- #
    def test_search_by_filename_keyword(self):
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.register_user("bob", PASS)
        self.svc.login("alice", PASS)
        s_a = cc.Signer.generate()
        self.svc.submit_file("FILE-A1", "采购合同.pdf", ORIGINAL, s_a, PASS)
        self.svc.submit_file("FILE-A2", "年度报告.docx", ORIGINAL2, s_a, PASS)
        self.svc.logout()
        self.svc.login("bob", PASS)
        s_b = cc.Signer.generate()
        self.svc.submit_file("FILE-B1", "采购合同-v2.pdf", b"bob-content", s_b, PASS)
        # alice（admin）能看到全部
        self.svc.logout()
        self.svc.login("alice", PASS)
        hits = self.svc.search_evidence("采购")
        self.assertEqual(len(hits), 2)
        # bob（普通用户）只能看到自己的
        self.svc.logout()
        self.svc.login("bob", PASS)
        hits = self.svc.search_evidence("采购")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["file_id"], "FILE-B1")

    def test_search_keyword_in_semantic_index(self):
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        self.svc.submit_file("FILE-001", "purchase_contract_2026.pdf", ORIGINAL, s, PASS)
        # 关键词 "purchase"（文件名拆分）、"contract"、"2026" 都应命中
        self.assertTrue(self.svc.search_evidence("purchase"))
        self.assertTrue(self.svc.search_evidence("contract"))
        self.assertTrue(self.svc.search_evidence("2026"))

    # ---------------- P0-3 证据报告 ---------------- #
    def test_evidence_report_returns_all_fields(self):
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        r = self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)["receipt"]
        ev_no = r["evidence_no"]
        report = self.svc.evidence_report(ev_no)
        self.assertEqual(report["存证编号"], ev_no)
        self.assertIn("文件指纹(SM3)", report)
        self.assertIn("存证主体(公钥指纹)", report)
        self.assertIn("签名值(SM2)", report)
        self.assertIn("区块高度", report)
        self.assertIn("区块哈希", report)
        self.assertIn("出块节点", report)
        self.assertIn("存证时间", report)
        self.assertIn("共识确认数", report)

    # ---------------- ③ 密文 C 独立落盘 ---------------- #
    def test_cipher_written_as_independent_file(self):
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)
        rec = self.svc._files["FILE-001"]
        # 内存态不再存 cipher_hex，改为 cipher_path
        self.assertNotIn("cipher_hex", rec)
        self.assertIn("cipher_path", rec)
        # 密文文件真实落盘
        import os
        self.assertTrue(os.path.isfile(rec["cipher_path"]))
        self.assertTrue(rec["cipher_path"].endswith(".enc"))
        # 落盘的是密文而非原文
        with open(rec["cipher_path"], "rb") as f:
            disk_cipher = f.read()
        self.assertNotEqual(disk_cipher, ORIGINAL)   # 不是原文
        self.assertEqual(disk_cipher, cc.sm4_encrypt(
            cc.derive_sm4_key_v2(PASS, bytes.fromhex(rec["salt"])), ORIGINAL))

    def test_decrypt_reads_from_cipher_file(self):
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)
        # 删除内存中的 cipher_hex（新存证本就没有），且删除内存态也应能从密文文件解密
        plain = self.svc.decrypt_file("FILE-001", PASS)
        self.assertEqual(plain, ORIGINAL)
        # 错误口令拒绝
        with self.assertRaises(ValueError):
            self.svc.decrypt_file("FILE-001", WRONG_PASS)

    def test_cipher_path_recorded_in_db(self):
        from app.models import Evidence
        from sqlalchemy.orm import Session
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)
        with Session(self.engine) as sess:
            rows = sess.query(Evidence).filter(Evidence.file_name == "采购合同.pdf").all()
            self.assertTrue(rows)
            self.assertTrue(all(r.cipher_path for r in rows))

    def test_historical_cipher_hex_fallback(self):
        """历史快照中只有 cipher_hex（无密文文件）时仍可解密。"""
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)
        rec = self.svc._files["FILE-001"]
        # 模拟历史态：删掉密文文件，仅留 cipher_hex
        import os
        os.remove(rec["cipher_path"])
        rec.pop("cipher_path", None)
        salt_hex = rec["salt"]
        key = cc.derive_sm4_key_v2(PASS, bytes.fromhex(salt_hex))
        rec["cipher_hex"] = cc.sm4_encrypt(key, ORIGINAL).hex()
        plain = self.svc.decrypt_file("FILE-001", PASS)
        self.assertEqual(plain, ORIGINAL)

    # ---------------- ④ 明文保存供验真 ---------------- #
    def test_save_recovered_file_default_and_custom(self):
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)
        # 默认目录
        p1 = self.svc.save_recovered_file("采购合同.pdf", ORIGINAL)
        import os
        self.assertTrue(os.path.isfile(p1))
        with open(p1, "rb") as f:
            self.assertEqual(f.read(), ORIGINAL)
        # 自定义路径
        custom = os.path.join(self._tmpdir, "out", "my_recovered.pdf")
        p2 = self.svc.save_recovered_file("采购合同.pdf", ORIGINAL, target_path=custom)
        self.assertEqual(p2, custom)
        with open(p2, "rb") as f:
            self.assertEqual(f.read(), ORIGINAL)

    def test_decrypt_and_verify_then_verify_recovered(self):
        """解密保存的明文可作为 candidate 完成验真闭环。"""
        self.svc.register_user("alice", PASS, role="admin")
        self.svc.login("alice", PASS)
        s = cc.Signer.generate()
        r = self.svc.submit_file("FILE-001", "采购合同.pdf", ORIGINAL, s, PASS)
        ev_no = r["receipt"]["evidence_no"]
        v = self.svc.decrypt_and_verify("FILE-001", PASS)
        self.assertTrue(v["ok"] and v["verified"])
        import os
        saved = self.svc.save_recovered_file(v["filename"], v["decrypted"],
                                              target_path=os.path.join(self._tmpdir, "rec.bin"))
        with open(saved, "rb") as f:
            recovered = f.read()
        self.assertTrue(self.svc.verify(ev_no, recovered)["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
