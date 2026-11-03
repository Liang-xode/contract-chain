# -*- coding: utf-8 -*-
"""
state_store.py —— 应用状态快照存储（链状态 / 密文记录的落盘与恢复）

定位：
  业务数据（用户/登录态/存证元数据）走 DAO 仓库落 SQLite/MySQL；
  而区块链本体（区块 / 交易）与密文属于「应用本地状态」，体量大且结构自洽，
  不适合塞进业务表，故以带原子写入的 JSON 快照持久化于此。

职责：
  - StateStore.load()  读取快照（不存在或损坏时返回 None，绝不抛栈打断启动）
  - StateStore.save()  原子写入（先写临时文件再替换，避免半截文件）
"""
import json
import os


class StateStore:
    """JSON 快照存储：负责链状态与密文记录的落盘 / 恢复。"""

    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict:
        """读取快照；文件不存在或内容损坏时返回 None（调用方按「无历史」处理）。"""
        if not self.path or not os.path.exists(self.path):
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (json.JSONDecodeError, OSError, ValueError):
            return None

    def save(self, data: dict) -> bool:
        """原子写入快照：先写 .tmp 再 os.replace，避免中途崩溃留下半截文件。"""
        if not self.path:
            return False
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False,indent=2)
        os.replace(tmp, self.path)
        return True

    def clear(self) -> bool:
        """删除快照（测试 / 重置用）。"""
        if self.path and os.path.exists(self.path):
            os.remove(self.path)
            return True
        return False
