# -*- coding: utf-8 -*-
"""
tests/test_demo.py —— 核心功能自动化测试

覆盖：SM2 公钥推导 / SM3 完整性 / SM4 加解密与私钥保护 /
      签名验签 / 完整业务流程 / 篡改检测 / 伪造检测 / 链上防篡改 / 重放检测

运行： cd contract-chain-demo &&  python -m unittest tests.test_demo -v
"""

import sys
import os
import time
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import sm2_keys, crypto as cc
from blockchain.chain import EvidenceChain
from sqlalchemy.orm import sessionmaker
from app.dao import build_engine
from app.models import Base
from app.service import FileEvidenceService

# 演示存证文件目录（test1.doc / 年度财务报表.xlsx / 采购框架协议.pdf 等）
DEMO_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo_files")


def demo_bytes(filename):
    with open(os.path.join(DEMO_DIR, filename), "rb") as f:
        return f.read()


class TestSM2Pubkey(unittest.TestCase):
    def test_deduction_deterministic(self):
        d = cc.func.random_hex(64)
        pub1 = sm2_keys.private_key_to_public_key(d)
        pub2 = sm2_keys.private_key_to_public_key(d)
        self.assertEqual(pub1, pub2)
        self.assertEqual(len(pub1), 128)

    def test_invalid_private_key(self):
        with self.assertRaises(ValueError):
            sm2_keys.private_key_to_public_key("0" * 64)  # d=0 非法


class TestSM3(unittest.TestCase):
    def test_avalanche(self):
        a = cc.sm3_hash(b"contract-a")
        b = cc.sm3_hash(b"contract-b")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_one_byte_change(self):
        base = b"hello world hello world hello"
        self.assertNotEqual(cc.sm3_hash(base), cc.sm3_hash(base[:-1] + b"X"))


class TestSM4(unittest.TestCase):
    def test_roundtrip(self):
        key = b"1234567890abcdef"
        data = "secret contract content 中文".encode("utf-8")
        cipher = cc.sm4_encrypt(key, data)
        self.assertEqual(cc.sm4_decrypt(key, cipher), data)

    def test_private_key_protection(self):
        s = cc.Signer.generate()
        cipher = cc.protect_private_key(s.private_key_hex, "pass")
        self.assertEqual(cc.unprotect_private_key(cipher, "pass"), s.private_key_hex)


class TestSignVerify(unittest.TestCase):
    def setUp(self):
        self.signer = cc.Signer.generate()

    def test_valid_sign(self):
        sig = self.signer.sign(b"payload")
        self.assertTrue(self.signer.verify(sig, b"payload"))

    def test_wrong_data_rejected(self):
        sig = self.signer.sign(b"payload")
        self.assertFalse(self.signer.verify(sig, b"other"))


class TestBusinessFlow(unittest.TestCase):
    """完整业务闭环 + 三重攻击检测"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="cc_demo_")
        # 隔离密文文件服务器，避免污染项目根目录
        os.environ["CONTRACT_CHAIN_CIPHER_STORE_DIR"] = os.path.join(self._tmpdir, "cipher_store")
        # 隔离数据库：使用临时 SQLite，避免向项目根 evidence.db 写入测试存证
        self._engine = build_engine(
            "sqlite:///" + os.path.join(self._tmpdir, "demo.db").replace("\\", "/"))
        Base.metadata.create_all(bind=self._engine)
        self.factory = sessionmaker(bind=self._engine, expire_on_commit=False)
        self.chain = EvidenceChain()
        self.svc = FileEvidenceService(self.chain, session_factory=self.factory)
        self.uploader = cc.Signer.generate()
        self.party2 = cc.Signer.generate()
        self.file_id = "FILE-TEST-001"
        self.filename = "test1.doc"
        self.raw = demo_bytes(self.filename)
        self.created = self.svc.submit_file(self.file_id, self.filename, self.raw,
                                            self.uploader, "pass")
        self.ev_no = self.created["receipt"]["evidence_no"]

    def tearDown(self):
        try:
            self._engine.dispose()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_chain_valid_after_submit(self):
        self.assertTrue(self.chain.is_chain_valid())

    def test_normal_verify_passes(self):
        v = self.svc.verify(self.ev_no, self.raw)
        self.assertTrue(v["passed"], v)

    def test_tamper_detected(self):
        v = self.svc.verify(self.ev_no, self.raw[:-1] + b"X")
        self.assertFalse(v["passed"])
        self.assertIn("完整性(SM3)", v["checks"])

    def test_unknown_evidence(self):
        v = self.svc.verify("0" * 16, self.raw)
        self.assertFalse(v["passed"])

    def test_sm4_decrypt_restores_file(self):
        """SM4 保密性闭环：正确口令解密还原原始文件。"""
        self.assertEqual(self.svc.decrypt_file(self.file_id, "pass"), self.raw)

    def test_sm4_wrong_passphrase_rejected(self):
        """错误口令不能还原出原文（保密性生效）。"""
        # SM4 无认证，错误密钥下填充校验极低概率可能通过，故断言「不是原文」
        try:
            plain = self.svc.decrypt_file(self.file_id, "wrong-pass")
        except ValueError:
            plain = None
        self.assertNotEqual(plain, self.raw)

    def test_forged_signature_detected(self):
        forger = cc.Signer.generate()
        f_digest = cc.sm3_hash(self.raw)
        f_ts = time.time()
        f_payload = f"{self.file_id}|{f_digest}|{f_ts}".encode()
        forged = forger.sign(f_payload)
        # 用真实上传方公钥验签伪造者签名 -> 必须失败
        self.assertFalse(self.uploader.verify(forged, f_payload))

    def test_replay_attack_detected(self):
        """重放攻击：同一签名内容在【不同时间】复用旧签名冒充新签认，验签上下文不匹配。"""
        old_payload = f"{self.file_id}|{cc.sm3_hash(self.raw)}|{time.time() - 100}".encode()
        old_sig = self.uploader.sign(old_payload)
        # 用「新的时间戳」构造应验签的上下文，旧签名必然无法通过
        new_payload = f"{self.file_id}|{cc.sm3_hash(self.raw)}|{time.time()}".encode()
        self.assertFalse(self.uploader.verify(old_sig, new_payload))

    def test_chain_tamper_detected(self):
        tmp = EvidenceChain()
        svc = FileEvidenceService(tmp, session_factory=self.factory)
        r = svc.submit_file("T", "t.bin", b"data", self.uploader, "x")["receipt"]
        self.assertTrue(tmp.is_chain_valid())
        tmp.tamper_block(r["block_index"], "txs", [])
        self.assertFalse(tmp.is_chain_valid())


if __name__ == "__main__":
    unittest.main(verbosity=2)
