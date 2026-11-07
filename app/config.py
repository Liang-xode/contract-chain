# -*- coding: utf-8 -*-
"""
config.py —— 持久化层全局配置

设计目标：起步 SQLite（零依赖、开箱即用），后期只需改一个连接串即可切换 MySQL。

切换方式（三选一）：
  1. 直接改下面的 DATABASE_URL 常量；
  2. 设置环境变量 CONTRACT_CHAIN_DATABASE_URL（无需改代码，优先级更高）；
  3. 给 FileEvidenceService 传入自定义 session_factory（测试用）。

MySQL 连接串示例（需驱动 PyMySQL，已加入 requirements.txt）：
  mysql+pymysql://root:your-password@127.0.0.1:3306/contract_chain?charset=utf8mb4
"""

import os

# 项目根目录（供把相对的 sqlite 路径解析为绝对路径，避免受启动目录影响）
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 默认：SQLite 本地文件（相对项目根目录 -> <项目根>/evidence.db）
DATABASE_URL = os.environ.get("CONTRACT_CHAIN_DATABASE_URL", "sqlite:///evidence.db")

# 切换 MySQL 时把上面一行替换为（或直接设环境变量）：
# DATABASE_URL = "mysql+pymysql://root:your-password@127.0.0.1:3306/contract_chain?charset=utf8mb4"

# 是否打印 SQL 语句（调试用）：设置 CONTRACT_CHAIN_DATABASE_ECHO=1 开启
DATABASE_ECHO = os.environ.get("CONTRACT_CHAIN_DATABASE_ECHO", "0") == "1"

# 链状态快照文件：区块链本体（区块/交易）与密文记录落盘于此，重启后自动恢复，
# 从而「重启不丢历史存证」且历史文件仍可口令授权解密。可用环境变量覆盖。
# 说明：该文件是应用本地状态（与业务库同目录），不随 DATABASE_URL 切换数据库而迁移。
STATE_PATH = os.environ.get(
    "CONTRACT_CHAIN_STATE_PATH", os.path.join(BASE_DIR, "evidence_state.json")
)

# 密文文件服务器：SM4 加密后的密文 C 以独立 .enc 文件落盘于此（不进业务库、不落原文 / 私钥 / 会话密钥）。
# 接收方凭 file_id + 授权口令从此目录读取密文 C 并解密还原。可用环境变量覆盖（测试 / 多实例隔离）。
CIPHER_STORE_DIR = os.environ.get(
    "CONTRACT_CHAIN_CIPHER_STORE_DIR", os.path.join(BASE_DIR, "cipher_store")
)

# 授权解密后还原的明文默认保存目录（用户可在「另存为」对话框中改到任意路径）。
RECOVERED_DIR = os.environ.get(
    "CONTRACT_CHAIN_RECOVERED_DIR", os.path.join(BASE_DIR, "recovered")
)

# ---- AI 语义赋能配置 ----
# 是否启用 LLM 语义索引（关闭时走关键词 LIKE 兜底，不报错）
LLM_ENABLED = os.environ.get("CONTRACT_CHAIN_LLM_ENABLED", "1") == "1"
# LLM 服务地址（兼容 OpenAI 协议，如 https://api.openai.com/v1 或本地兼容端点）
LLM_API_BASE = os.environ.get(
    "CONTRACT_CHAIN_LLM_API_BASE", "https://open.bigmodel.cn/api/paas/v4")
# LLM API Key（留空表示匿名/本地端点；建议通过环境变量注入，避免硬编码进源码）
LLM_API_KEY = os.environ.get("CONTRACT_CHAIN_LLM_API_KEY", "")
# 语义索引模型名（如 gpt-4o-mini、qwen-plus 等）
LLM_MODEL = os.environ.get("CONTRACT_CHAIN_LLM_MODEL", "glm-5.3-flash")

# ---- 语义索引：正文抽取（路线 A）----
# 是否允许把「正文节选」发送给 LLM 生成摘要（隐私开关，默认开启）。
# 关闭时仅用「文件名 + 非敏感元数据」生成索引（即旧行为），正文不出本机。
# 说明：正文节选只在内存中处理、绝不落库；密文与私钥在任何情况下都不外发。
SEMANTIC_LLM_READS_CONTENT = os.environ.get(
    "CONTRACT_CHAIN_SEMANTIC_LLM_READS_CONTENT", "1") == "1"
# 发送给 LLM 的正文节选最大字数（控制 token 成本与隐私暴露面）
SEMANTIC_CONTENT_MAX_CHARS = int(os.environ.get(
    "CONTRACT_CHAIN_SEMANTIC_CONTENT_MAX_CHARS", "2000"))

# ---- 语义向量检索（路线 B）----
# 是否启用向量语义检索（关闭时仅走关键词匹配，不报错）
EMBEDDING_ENABLED = os.environ.get("CONTRACT_CHAIN_EMBEDDING_ENABLED", "1") == "1"
# 向量模型名（智谱 embedding-3，与 LLM_API_BASE 共用同一端点）
EMBEDDING_MODEL = os.environ.get("CONTRACT_CHAIN_EMBEDDING_MODEL", "embedding-3")
# 本地向量索引文件（派生数据，可随时重建；不含原文）
SEMANTIC_VECTOR_PATH = os.environ.get(
    "CONTRACT_CHAIN_SEMANTIC_VECTOR_PATH",
    os.path.join(BASE_DIR, "semantic_vectors.json"))
