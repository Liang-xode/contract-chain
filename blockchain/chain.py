# -*- coding: utf-8 -*-
"""
chain.py —— 模拟联盟链（区块链存证层）

用轻量本地实现还原联盟链核心语义，用于课程/竞赛原型演示：
    - 区块 + 交易 + 链式哈希（防篡改）
    - 简单 PBFT 风格共识（多节点投票）
    - 存证上链 / 按存证号查询 / 区块浏览器

说明：demo 为教学级单进程实现；真实竞赛版可替换为 FISCO BCOS / Ganache，
本模块对外接口保持一致，便于无缝替换。
"""

import hashlib
import json
import time
from typing import Optional


def _sha256(data: bytes) -> str:
    """区块头部使用 SHA-256 做区块哈希（区块链本身的安全，非业务指纹，业务指纹用 SM3）。"""
    return hashlib.sha256(data).hexdigest()


class Transaction:
    """链上存证交易：承载 SM3 合同指纹 + SM2 签名 + 主体与时间，原文永不上链。"""

    def __init__(self, evidence_no: str, contract_hash: str, signer_fp: str,
                 signature: str, pubkey: str, ts: float, extra: str = ""):
        self.evidence_no = evidence_no      # 存证编号
        self.contract_hash = contract_hash  # SM3 合同指纹
        self.signer_fp = signer_fp          # 签名主体公钥指纹
        self.signature = signature          # SM2 签名
        self.pubkey = pubkey                # 签名者公钥
        self.ts = ts                        # 存证时间戳
        self.extra = extra                  # 附加信息（如参与方列表）

    def to_dict(self) -> dict:
        return {
            "evidence_no": self.evidence_no,
            "contract_hash": self.contract_hash,
            "signer_fp": self.signer_fp,
            "signature": self.signature,
            "pubkey": self.pubkey,
            "ts": self.ts,
            "extra": self.extra,
        }

    def raw_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")


class Block:
    """区块：头部哈希引用前一区块，形成不可篡改的链。"""

    def __init__(self, index: int, txs: list, prev_hash: str, validator: str):
        self.index = index
        self.txs = txs
        self.prev_hash = prev_hash
        self.validator = validator          # 出块/共识节点标识
        self.timestamp = time.time()
        self.nonce = 0
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        body = json.dumps([t.to_dict() for t in self.txs], sort_keys=True).encode()
        head = f"{self.index}|{self.prev_hash}|{self.validator}|{self.timestamp}|{self.nonce}".encode()
        return _sha256(head + body)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "validator": self.validator,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "tx_count": len(self.txs),
            "txs": [t.to_dict() for t in self.txs],
        }


class EvidenceChain:
    """
    模拟联盟链。多节点共同维护一条链，存证交易经「广播 → 节点校验 → 共识 → 出块」写入。
    """

    GENESIS_PREV = "0" * 64

    def __init__(self, nodes: list = None, required_confirmations: int = 2):
        self.nodes = nodes or ["node-A", "node-B", "node-C"]  # 联盟链授权节点
        self.required = required_confirmations                # 共识所需确认数
        self._chain: list[Block] = [self._genesis()]
        self._by_evidence: dict[str, tuple] = {}              # 存证编号 -> (区块索引, 交易索引)
        self.confirmations: dict[str, int] = {}               # 存证编号 -> 确认数

    def _genesis(self) -> Block:
        return Block(0, [], self.GENESIS_PREV, self.nodes[0])

    # ---- 区块浏览器 ----
    def latest_block(self) -> Block:
        return self._chain[-1]

    def height(self) -> int:
        return len(self._chain) - 1

    def chain(self) -> list:
        return [b.to_dict() for b in self._chain]

    # ---- 存证上链 ----
    def submit_evidence(self, tx: Transaction) -> dict:
        """广播存证交易，节点校验后经共识出块上链。"""
        # 1) 节点校验（简易）
        if not (tx.contract_hash and tx.signature and tx.pubkey):
            raise ValueError("存证数据不完整，节点拒绝")
        # 2) 模拟 PBFT：多节点投票确认
        votes = min(self.required, len(self.nodes))
        # 3) 出块（本轮所有确认的交易打包进新块）
        block = Block(self.height() + 1, [tx], self.latest_block().hash, self.nodes[votes - 1])
        self._chain.append(block)
        pos = (block.index, 0)
        self._by_evidence[tx.evidence_no] = pos
        self.confirmations[tx.evidence_no] = votes
        return {
            "evidence_no": tx.evidence_no,
            "block_index": block.index,
            "block_hash": block.hash,
            "validator": block.validator,
            "confirmations": votes,
            "timestamp": tx.ts,
        }

    # ---- 存证查询 ----
    def query_evidence(self, evidence_no: str) -> Optional[dict]:
        pos = self._by_evidence.get(evidence_no)
        if pos is None:
            return None
        block_index, tx_index = pos
        block = self._chain[block_index]
        tx = block.txs[tx_index]
        return {"block": block.to_dict(), "transaction": tx.to_dict()}

    # ---- 链完整性自检 ----
    def is_chain_valid(self) -> bool:
        """验证整条链：每个区块哈希正确 + 前后哈希衔接。用于演示链上不可篡改。"""
        for i in range(1, len(self._chain)):
            cur, prev = self._chain[i], self._chain[i - 1]
            if cur.hash != cur._compute_hash():
                return False
            if cur.prev_hash != prev.hash:
                return False
        return True

    def tamper_block(self, block_index: int, field: str, value):
        """
        演示用：篡改某个区块的内容，模拟攻击者直接改写链上数据。
        注意：篡改后【不】重算区块哈希 —— 这与真实联盟链语义一致：
        单节点改写数据会导致「哈希与内容不符」，被其它节点的全链校验拒绝。
        """
        block = self._chain[block_index]
        setattr(block, field, value)
        # 哈希保持不变 -> 与内容不一致，is_chain_valid 将判定篡改
