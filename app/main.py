# -*- coding: utf-8 -*-
"""
main.py —— 命令行演示入口（Demo 一键运行）

展示「国密区块链通用电子文件加密存证系统」：
    [存证]  任意电子文件（合同/论文/病历/源代码…）-> SM3 指纹 -> 上传方 SM2 签名
            -> SM4 加密 -> 联盟链共识上链 -> 多方签认
    [验真]  三重校验：完整性 / 签名合法性 / 链上一致性
    [攻击]  篡改 1 字节 / 伪造签名 / 篡改链上区块 -> 系统全部识别

运行：  cd contract-chain-demo  &&  python -m app.main
"""

import time

from crypto import crypto as cc
from blockchain.chain import EvidenceChain
from app.service import FileEvidenceService

LINE = "=" * 62
SUB = "-" * 62


def p(title):
    print(f"\n{LINE}\n  {title}\n{LINE}")


def step(text):
    print(f"    [{time.strftime('%H:%M:%S')}] {text}")


def demo_files():
    """演示用：多种类型的电子文件（模拟读取后的字节流）。"""
    return [
        ("采购框架协议.pdf", "甲乙双方就 2026 年度办公设备采购达成框架协议……（合同原文）".encode("utf-8")),
        ("毕业论文_定稿.docx", "基于国密算法的可信存证系统设计与实现……（论文正文）".encode("utf-8")),
        ("体检报告_张某某.jpg", "这是一张体检报告的影像扫描件……".encode("utf-8")),
        ("核心源码_main.py.zip", "def main(): print('system core')  # 源代码打包".encode("utf-8")),
        ("财务报表_Q3.xlsx", "2026 年第三季度营收与利润明细表……".encode("utf-8")),
    ]


def main():
    print(f"\n{LINE}")
    print("   国密区块链通用电子文件加密存证系统 —— 竞赛级原型 Demo")
    print("   SM2 签名 / SM3 指纹 / SM4 加密 / 联盟链存证 / 三重验真")
    print("   适用：合同 / 论文 / 病历 / 图纸 / 源代码 / 报表 等任意电子文件")
    print(LINE)

    chain = EvidenceChain(nodes=["node-A", "node-B", "node-C"], required_confirmations=2)
    svc = FileEvidenceService(chain)
    uploader = cc.Signer.generate()
    auditor = cc.Signer.generate()
    print(f"\n  联盟链节点: {chain.nodes}   共识确认数: {chain.required}")

    # ==================================================================
    p("① 批量文件存证：5 类电子文件统一走「SM3 指纹 + SM2 签名 + SM4 加密 + 上链」")
    receipts = []
    for i, (fname, content) in enumerate(demo_files(), start=1):
        file_id = f"FILE-{i:03d}"
        step(f"存证 [{fname}]（{len(content)} 字节）...")
        r = svc.submit_file(file_id, fname, content, uploader, "demo-pass",
                            meta={"归属单位": "示例实验室", "类型": fname.rsplit(".", 1)[-1]})
        receipts.append(r)
        print(f"    ✅ [{fname}] 指纹={r['digest'][:16]}... 存证号={r['receipt']['evidence_no']} "
              f"区块#{r['receipt']['block_index']} 确认{r['receipt']['confirmations']}")

    # ==================================================================
    p("② 多方签认：审计方对「采购框架协议.pdf」追加 SM2 签名并上链")
    contract_file = ("采购框架协议.pdf", demo_files()[0][1])
    added = svc.add_signer("FILE-001", contract_file[0], contract_file[1], auditor)
    print(f"    ✅ 签认主体: {added['signer']}   存证号: {added['receipt']['evidence_no']}")

    # ==================================================================
    p("③ SM4 授权解密还原（保密性完整闭环）")
    original = demo_files()[0][1]
    recovered = svc.decrypt_file("FILE-001", "demo-pass")
    if recovered == original:
        print("    ✅ 正确口令解密成功：SM4 密文还原出原始文件，内容与原文一致")
    step("尝试用错误口令解密...")
    try:
        svc.decrypt_file("FILE-001", "wrong-pass")
        print("    ⚠️ 异常：错误口令竟解密成功（不应发生）")
    except ValueError as e:
        print(f"    ❌ 错误口令被拒绝：{e}")

    # ==================================================================
    p("④ 正常验真：三重校验全部通过（以采购框架协议为例）")
    v = svc.verify(receipts[0]["receipt"]["evidence_no"], contract_file[1])
    for k, res in v["checks"].items():
        mark = "✅" if res.startswith("通过") else "❌"
        print(f"    {mark} {k}: {res.splitlines()[0]}")
    print(f"    {'🎉 验真结论：文件完整、签名有效、存证可信' if v['passed'] else '验真未通过'}")

    # ==================================================================
    p("⑤ 攻击演示 A —— 篡改文件 1 字节")
    tampered = contract_file[1][:-1] + b"X"
    step("攻击者修改文件最后一个字节后重新验真...")
    v = svc.verify(receipts[0]["receipt"]["evidence_no"], tampered)
    for k, res in v["checks"].items():
        mark = "✅" if res.startswith("通过") else "❌"
        print(f"    {mark} {k}: {res.splitlines()[0]}")
    print(f"    ❌ 篡改检测：{v['reason']}  —— 系统成功识别文件被修改")

    # ==================================================================
    p("⑥ 攻击演示 B —— 伪造签名（用无关私钥冒充上传方）")
    forger = cc.Signer.generate()
    f_digest = cc.sm3_hash(contract_file[1])
    f_ts = time.time()
    f_payload = f"FILE-001|{f_digest}|{f_ts}".encode()
    forged_sig = forger.sign(f_payload)
    step("伪造者用自己私钥对文件内容签名，声称自己是上传方...")
    if uploader.verify(forged_sig, f_payload):
        print("    ⚠️ 异常：伪造签名竟通过上传方验签（理论上不应发生）")
    else:
        print("    ✅ 不可否认性：用真实上传方公钥验签伪造签名 -> 失败，冒充被识破")

    # ==================================================================
    p("⑦ 攻击演示 C —— 篡改链上区块数据（去中心化防篡改）")
    step("构造临时链提交一笔存证，再直接篡改其区块内容...")
    tmp_chain = EvidenceChain(nodes=["node-A", "node-B", "node-C"], required_confirmations=2)
    tmp_svc = FileEvidenceService(tmp_chain)
    tmp_receipt = tmp_svc.submit_file("TMP-1", "测试文件.bin", b"data", uploader, "x")["receipt"]
    tmp_chain.tamper_block(tmp_receipt["block_index"], "txs", [])
    step("篡改后执行全链一致性校验（每个区块哈希 + 前后衔接）...")
    if not tmp_chain.is_chain_valid():
        print("    ✅ 链完整性校验失败：区块哈希断裂，链上篡改被发现（要真正通过需控制 2/3 节点）")
    else:
        print("    ⚠️ 篡改未被本地自检发现")
    print("    ℹ️ 主链存证未受影响，继续展示凭证")

    # ==================================================================
    p("⑧ 存证凭证（可交付证据）")
    report = svc.evidence_report(receipts[0]["receipt"]["evidence_no"])
    for k, val in report.items():
        v_str = val if len(str(val)) <= 48 else str(val)[:24] + "..." + str(val)[-16:]
        print(f"    {k:<14}: {v_str}")

    print(f"\n{LINE}\n  演示结束：任意电子文件「存证→签认→验真→篡改/伪造/链上攻击」闭环\n{LINE}")


if __name__ == "__main__":
    main()
