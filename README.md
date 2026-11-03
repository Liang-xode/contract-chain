# 国密区块链通用电子文件加密存证系统 —— 竞赛级原型 

基于 **SM2 / SM3 / SM4 全栈国密算法 + 联盟链存证** 的**任意电子文件**可信加密存证原型。
不限于电子合同，覆盖 合同 / 论文 / 病历 / 图纸 / 源代码 / 报表 等文件类型，
内置「正常流程 + 篡改/伪造/链上攻击」三重攻防演示，适合密码学/网络安全/信创类竞赛答辩。

## 特性
- **SM3** 生成文件指纹（完整性校验）
- **SM2** 数字签名 / 验签（身份认证 + 不可否认性），私钥经 SM4 加密保护存储
- **SM4** 对称加密文件原文（保密性），原文永不上链
- **模拟联盟链**：区块 + 链式哈希 + PBFT 风格多节点共识，存证去中心化防篡改
- **三重验真**：完整性 / 签名合法性 / 链上一致性
- **多文件类型**：`submit_file` 接收任意文件字节流，附文件名/类型/大小元数据

## 数据库架构

默认使用 SQLite（项目根 `evidence.db`），只需改连接串即可切换 MySQL（`CONTRACT_CHAIN_DATABASE_URL`），业务代码零改动。

**存储分层（业务库不碰原文）**

| 位置 | 内容 | 安全边界 |
|------|------|----------|
| 业务库 `evidence.db` / MySQL | `users` / `sessions` / `evidence` / `signer` 四表 | 仅指纹、公钥、签名、密文路径；无原文 / 口令 / 私钥 / 会话密钥 |
| `evidence_state.json` | 区块、交易、存证索引、确认数、密文元数据（cipher_hex + salt） | 无明文、无 SM4 会话密钥 |
| `cipher_store/<file_id>.enc` | SM4 密文 C（独立文件，不进库） | 密文，需授权口令派生密钥才可解 |
| `recovered/` | 授权解密后用户主动保存的明文 | 明文只在授权方本地 |
| `~/.xincain/keystore/{username}.pem` | SM2 私钥（口令经 SM4 加密落盘） | 私钥加密保护，绝不上链 / 入库 |

**ER 关系**

```
users (1) ──< sessions   user_id      登录态，登出删除 / 重置密码批量吊销
users (1) ──< evidence   uploader_id  可空；NULL = 匿名存证（未登录上传）
users (1) ──< signer     user_id      可空；删除用户后置 NULL（登记保留）
```

**4 张表字段**

| 表 | 关键字段 | 约束 / 索引 |
|----|----------|-------------|
| `users` | id, username, password_hash, salt, role, status, display_name, created_at, updated_at | `username` 唯一；口令为 PBKDF2-HMAC-SHA256 加盐哈希，不存明文；`role` = superadmin / admin / user；`status` = enabled / disabled |
| `sessions` | id, user_id, token, created_at, expires_at | `user_id` FK→users.id（索引）；`token` 唯一（64 位 hex） |
| `evidence` | id, file_id, file_sha256, file_name, signer_pubkey, signature, chain_hash, semantic_index, cipher_path, uploader_id, created_at | `file_sha256` 实存 SM3 指纹（索引）；`file_id` / `cipher_path` / `uploader_id` 索引；`uploader_id` 可空（匿名）；**只增不改不删** |
| `signer` | id, name, pubkey, user_id, created_at | `pubkey` 唯一（SM2 公钥 hex）；`user_id` 可空（FK→users.id） |

**DAO 收口**：`app/models.py` 定义表结构，`app/dao/database.py` 负责引擎 / 会话 / 自动建表 / 幂等补列迁移，`app/dao/repository.py` 的 4 个仓库类（User / Session / Evidence / Signer）是业务层与 GUI 唯一的数据读写入口，业务层禁止直接写 SQL。`EvidenceRepository` 不提供 update / delete，从数据层保证存证不可篡改。

**权限可见性**：superadmin / admin 可见全部存证，普通用户仅见本人上传，未登录仅见匿名存证；检索页空检索词即按该范围列出，关键词过滤仍不越权。

## 环境与运行
```bash
pip install -r requirements.txt        # 依赖：gmssl、PyQt5、SQLAlchemy、PyMySQL
python -m app.main                     # 运行完整业务与攻防演示（5 类文件批量存证）
python -m app.gui                      # 启动 PyQt5 图形界面（或双击 run_gui.bat）
python -m unittest tests.test_demo tests.test_integration_phase12 tests.test_persistence -v  # 56 项测试
python -m crypto.crypto                # 国密算法冒烟自测
python -m crypto.sm2_keys              # SM2 公钥推导自测
```

## 目录结构
```
crypto/sm2_keys.py          自实现 SM2 椭圆曲线点运算（私钥推导公钥）
crypto/crypto.py            国密统一封装层（SM2/SM3/SM4 + KeyStore 私钥保护）
blockchain/chain.py         模拟联盟链（区块、共识、存证、链完整性校验）
app/config.py               持久化配置（DATABASE_URL / 快照 / 密文目录）
app/models.py               4 张表的 ORM 模型
app/dao/database.py         引擎 / 会话工厂 / 自动建表 / 幂等补列迁移
app/dao/security.py         PBKDF2-HMAC-SHA256 加盐哈希
app/dao/repository.py       4 个仓库类（业务层唯一数据读写入口）
app/dao/cipher_store.py     密文文件存取
app/dao/state_store.py      链状态快照读写
app/service.py              业务逻辑（存证、签认、三重验真、检索、解密、凭证）
app/main.py                 命令行演示入口
app/gui.py / gui.ui         PyQt5 桌面界面
app/login.py / login.ui     登录对话框
demo_files/                 演示存证文件（doc/ppt/txt/xlsx/jpg/docx/pdf/zip）
tests/test_demo.py          核心算法与业务闭环测试（17 例）
tests/test_integration_phase12.py  集成验收：KDF / 密钥 / 解密 / 检索（14 例）
tests/test_persistence.py   持久化 / 登录 / 权限 / 检索验收（25 例）
run_gui.bat                 GUI 一键启动脚本（自动装缺失依赖）
```

## 测试说明（tests 目录）

| 文件 | 作用 |
|------|------|
| `test_demo.py` | 核心功能单元测试：SM2 公钥推导、SM3 雪崩效应、SM4 往返与私钥保护、签名验签；完整业务闭环与篡改 / 伪造 / 重放 / 链上篡改四类攻击检测；SM4 正确口令还原、错误口令拒绝 |
| `test_integration_phase12.py` | Phase 1+2+3 集成验收：PBKDF2 KDF 与每文件独立 salt、账号密钥 KeyStore 首登生成 / 二次加载、解密验真闭环、密文独立 `.enc` 与 `cipher_path` 入库、历史 `cipher_hex` 兼容、另存 `recovered`、关键词检索、证据报告字段 |
| `test_persistence.py` | 持久化层验收：四表建表与字段、注册登录全流程、口令加盐哈希、库文件无明文秘密、权限归属、MySQL dialect 可切换、链快照重启恢复、存证仓库无 update/delete、超管启停 / 删除用户 / 重置密码、`file_id` 检索、空检索可见范围与越权不可见 |

> 三个测试文件均为临时 SQLite + 临时密文目录隔离，跑完不污染项目根 `evidence.db`；演示文件统一取自 `demo_files/`。

## 核心设计原则
> 原文不上链，指纹上链；私钥不出本地，签名上链。

生产 / 竞赛正式版可将 `blockchain/chain.py` 替换为 **FISCO BCOS（原生国密）** 或 **Ganache + web3.py**，对外接口不变。
