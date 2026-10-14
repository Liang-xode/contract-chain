# 国密区块链通用电子文件加密存证系统 —— 竞赛级原型 Demo

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

## 环境与运行
```bash
pip install -r requirements.txt        # 依赖：gmssl、PyQt5
python -m app.main                     # 运行完整业务与攻防演示（5 类文件批量存证）
python -m app.gui                      # 启动 PyQt5 图形界面（或双击 run_gui.bat）
python -m unittest tests.test_demo -v  # 运行 15 项自动化测试
python -m crypto.crypto                # 国密算法冒烟自测
python -m crypto.sm2_keys              # SM2 公钥推导自测
```

## 目录结构
```
crypto/sm2_keys.py   自实现 SM2 椭圆曲线点运算（私钥推导公钥）
crypto/crypto.py     国密统一封装层（SM2/SM3/SM4 + 私钥保护）
blockchain/chain.py  模拟联盟链（区块、共识、存证、链完整性校验）
app/service.py       业务逻辑（submit_file 存证、add_signer 签认、三重验真、凭证）
app/main.py          命令行演示入口
app/gui.py           PyQt5 桌面界面（拖拽上传/一键签署/验真红绿图标/实时日志）
run_gui.bat          GUI 一键启动脚本（自动装缺失依赖）
tests/test_demo.py   自动化测试（15 例）
```

## 核心设计原则
> 原文不上链，指纹上链；私钥不出本地，签名上链。

生产 / 竞赛正式版可将 `blockchain/chain.py` 替换为 **FISCO BCOS（原生国密）** 或 **Ganache + web3.py**，对外接口不变。
