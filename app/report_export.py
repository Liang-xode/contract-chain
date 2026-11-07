# -*- coding: utf-8 -*-
"""
report_export.py —— 报告导出（DOCX / PDF），两种模板严格区分

模板定位：
- receipt（存证凭证）：单条存证的「已上链」回执。一页、凭证感、结论一句话。
  面向：交付给存证方自己保存，证明"这份文件在何时被谁以何种指纹写入了哪条链的哪个区块"。
- proof（证据报告）：第三方可采信的「鉴定式」报告。分章节、含三重校验结论与声明。
  面向：交给审计方 / 法院 / 监管方复核，回答"文件是否被篡改、签名是否有效、是否足以上链存证"。

两种模板共用同一套「块模型」，但章节、结论口径、声明文字完全不同，不做同一个模板换标题。
"""

import io
import os
import re
import time

# ---------------------------------------------------------------- 字体

_FONT_CANDIDATES = (
    ("SimHei", r"C:\Windows\Fonts\simhei.ttf"),
    ("MicrosoftYaHei", r"C:\Windows\Fonts\msyh.ttc"),
    ("SimSun", r"C:\Windows\Fonts\simsun.ttc"),
)

_pdf_font_name = None


def _pdf_font() -> str:
    """注册中文字体，返回 reportlab 可用的字体名；全部缺失时回退 Helvetica。"""
    global _pdf_font_name
    if _pdf_font_name:
        return _pdf_font_name
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    for name, path in _FONT_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            if path.lower().endswith(".ttc"):
                pdfmetrics.registerFont(TTFont(name, path, subfontIndex=0))
            else:
                pdfmetrics.registerFont(TTFont(name, path))
            _pdf_font_name = name
            return name
        except Exception:
            continue
    _pdf_font_name = "Helvetica"
    return _pdf_font_name


def _docx_font(run, name="微软雅黑"):
    from docx.oxml.ns import qn

    run.font.name = name
    run._element.rPr.rFonts.set(qn("w:eastAsia"), name)


# ---------------------------------------------------------------- 数据组装

def build_receipt(data: dict) -> dict:
    """由 service.receipt_report() 的原始字段组装「存证凭证」块模型。"""
    fields = [
        ("存证编号", data.get("存证编号", "")),
        ("文件名称", data.get("文件名称", "")),
        ("文件类型 / 大小", data.get("文件规格", "")),
        ("SM3 指纹", data.get("文件指纹(SM3)", "")),
        ("存证主体（公钥指纹）", data.get("存证主体(公钥指纹)", "")),
        ("SM2 签名值", data.get("签名值(SM2)", "")),
        ("区块高度", data.get("区块高度", "")),
        ("区块哈希", data.get("区块哈希", "")),
        ("出块节点", data.get("出块节点", "")),
        ("存证时间", data.get("存证时间", "")),
        ("共识确认数", data.get("共识确认数", "")),
    ]
    semantic = []
    if data.get("语义摘要"):
        semantic.append(("AI 语义摘要", data["语义摘要"]))
    if data.get("语义关键词"):
        semantic.append(("AI 关键词", "、".join(data["语义关键词"])))
    if data.get("语义类别"):
        semantic.append(("AI 分类", data["语义类别"]))

    sections = [("存证信息", fields)]
    if semantic:
        sections.append(("AI 语义索引", semantic))

    return {
        "kind": "receipt",
        "title": "电子文件存证凭证",
        "subtitle": "国密 SM3 指纹 · SM2 数字签名 · 联盟链存证回执",
        "meta": [
            ("凭证编号", data.get("凭证编号", "")),
            ("出具时间", data.get("出具时间", "")),
        ],
        "sections": sections,
        "conclusion_label": "存证结论",
        "conclusion": data.get("结论") or (
            "该文件已于 %s 由 %s 以 SM2 签名提交，写入联盟链区块 #%s（出块节点 %s），"
            "当前共识确认数 %s。任何人持同一文件即可重新计算 SM3 指纹并与链上记录比对。"
            % (data.get("存证时间", ""), data.get("存证主体(公钥指纹)", ""),
               data.get("区块高度", ""), data.get("出块节点", ""),
               data.get("共识确认数", ""))
        ),
        "conclusion_ok": True,
        "statement": [],
        "footer": "本凭证由「信链」系统依据本机存证库与联盟链状态快照自动生成，"
                  "仅证明该指纹在所述时间已被写入所述区块，不构成对文件内容合法性的评价。",
    }


def build_proof(data: dict) -> dict:
    """由 service.proof_report() 的原始字段组装「证据报告」块模型（分七章）。"""
    checks = data.get("checks") or {}
    check_rows = [(k, v) for k, v in checks.items()]

    basic = [
        ("存证编号", data.get("存证编号", "")),
        ("文件名称", data.get("文件名称", "")),
        ("文件类型 / 大小", data.get("文件规格", "")),
        ("归属单位", data.get("归属单位", "") or "未登记"),
        ("上传者公钥指纹", data.get("存证主体(公钥指纹)", "")),
    ]
    integrity = [
        ("摘要算法", "SM3（GB/T 32905-2016）"),
        ("链上指纹", data.get("文件指纹(SM3)", "")),
        ("重算指纹", data.get("重算指纹", "") or "未提供待核验文件"),
        ("比对结果", data.get("完整性结论", "")),
    ]
    chain = [
        ("区块高度", data.get("区块高度", "")),
        ("区块哈希", data.get("区块哈希", "")),
        ("出块节点", data.get("出块节点", "")),
        ("存证时间", data.get("存证时间", "")),
        ("共识确认数", data.get("共识确认数", "")),
    ]
    sign = [
        ("存证方签名算法", "SM2（GB/T 32918）"),
        ("存证方签名值", data.get("签名值(SM2)", "")),
        ("存证方验签结果", data.get("验签结论", "")),
        ("审计方公钥指纹", data.get("审计方指纹", "") or "无审计方签认"),
        ("审计方签认结果", data.get("审计签认结论", "") or "未检测：暂无审计方追加签认"),
    ]
    semantic = []
    if data.get("语义摘要"):
        semantic.append(("AI 语义摘要", data["语义摘要"]))
    if data.get("语义关键词"):
        semantic.append(("AI 关键词", "、".join(data["语义关键词"])))
    if data.get("语义类别"):
        semantic.append(("AI 分类", data["语义类别"]))

    sections = [
        ("一、基本信息", basic),
        ("二、完整性校验", integrity),
        ("三、链上存证信息", chain),
        ("四、数字签名与签认", sign),
    ]
    if semantic:
        sections.append(("五、AI 语义索引", semantic))
    if check_rows:
        sections.append(("六、三重校验明细", check_rows))

    return {
        "kind": "proof",
        "title": "电子数据证据报告",
        "subtitle": "完整性校验 · SM2 验签 · 联盟链核验 · 审计方签认",
        "meta": [
            ("报告编号", data.get("报告编号", "")),
            ("出具时间", data.get("出具时间", "")),
            ("出具方", data.get("出具方", "信链存证系统")),
        ],
        "sections": sections,
        "conclusion_label": "核验结论",
        "conclusion": data.get("结论", ""),
        # True=全部核验通过；False=未通过；None=部分核验（未提供原件，内容一致性未核验）
        "conclusion_ok": data.get("conclusion_ok", data.get("passed")),
        "statement": [
            "一、本报告依据《电子签名法》对电子签名可靠性的要求，逐项核验：文件指纹与链上记录是否一致、"
            "SM2 签名是否可验证、存证是否存在于联盟链且区块完整。",
            "二、若「完整性校验」标注为「未提供待核验文件」，则本次仅完成链上与签名核验，"
            "文件内容一致性须由持有原件的一方另行复核，本报告不就此作出肯定结论。",
            "三、AI 语义索引由大模型依据加密前抽取的正文节选生成，仅用于检索定位，"
            "不参与完整性、签名与链上核验结论，亦不得作为文件内容的解释依据。",
            "四、本报告不含文件原文、密文或任何私钥材料；报告由「信链」系统依据核验时刻的链状态快照生成，"
            "出具方对核验过程负责，结论的最终采信须由提交方与第三方复核方共同承担。",
        ],
        "footer": "本报告由「信链」系统自动生成，核验结果取决于核验时刻的链状态快照与所提供文件；"
                  "报告本身可随文件一并提交第三方复核。",
    }


def _wrap_long(value: str, width: int = 64) -> str:
    """把长 hex / 长串按固定宽度折行，避免表格溢出。"""
    if not isinstance(value, str):
        value = str(value)
    if len(value) <= width:
        return value
    if re.fullmatch(r"[0-9a-fA-F]+", value or ""):
        return "\n".join(value[i:i + width] for i in range(0, len(value), width))
    return value


def _prepared(block: dict) -> dict:
    """统一做长串折行 + 值规范化。"""
    def fix(v):
        if v is None:
            return ""
        if isinstance(v, bool):
            return "是" if v else "否"
        return _wrap_long(str(v))

    out = dict(block)
    out["meta"] = [(k, fix(v)) for k, v in block.get("meta", [])]
    out["sections"] = [
        (title, [(k, fix(v)) for k, v in rows]) for title, rows in block.get("sections", [])
    ]
    out["conclusion"] = fix(block.get("conclusion"))
    return out


# ---------------------------------------------------------------- DOCX

def write_docx(block: dict, path: str) -> str:
    block = _prepared(block)
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor

    doc = Document()
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.left_margin = Cm(2.2)
    section.right_margin = Cm(2.2)
    section.top_margin = Cm(2.0)
    section.bottom_margin = Cm(2.0)

    # 正文默认字体
    style = doc.styles["Normal"]
    style.font.name = "微软雅黑"
    style.font.size = Pt(10.5)
    style.element.rPr.rFonts.set(qn("w:eastAsia"), "微软雅黑")

    def add_text(text, size=10.5, bold=False, color=None, align=None, space_after=4):
        p = doc.add_paragraph()
        if align is not None:
            p.alignment = align
        p.paragraph_format.space_after = Pt(space_after)
        run = p.add_run(text)
        _docx_font(run, "黑体" if bold else "微软雅黑")
        run.font.size = Pt(size)
        run.bold = bold
        if color:
            run.font.color.rgb = RGBColor(*color)
        return p

    def add_multiline(cell_para, text, size=10, bold=False, color=None):
        lines = str(text).split("\n")
        for i, line in enumerate(lines):
            run = cell_para.add_run(line)
            _docx_font(run, "黑体" if bold else "微软雅黑")
            run.font.size = Pt(size)
            run.bold = bold
            if color:
                run.font.color.rgb = RGBColor(*color)
            if i != len(lines) - 1:
                run.add_break()

    def shade(cell, hex_color):
        tcPr = cell._tc.get_or_add_tcPr()
        el = OxmlElement("w:shd")
        el.set(qn("w:val"), "clear")
        el.set(qn("w:color"), "auto")
        el.set(qn("w:fill"), hex_color)
        tcPr.append(el)

    def set_borders(table, color="D9DEE7", size=4):
        tbl = table._tbl
        tblPr = tbl.tblPr
        borders = OxmlElement("w:tblBorders")
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            el = OxmlElement("w:%s" % edge)
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), str(size))
            el.set(qn("w:color"), color)
            borders.append(el)
        tblPr.append(borders)

    # 标题
    add_text(block["title"], size=20, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    add_text(block["subtitle"], size=9, color=(0x6B, 0x72, 0x80),
             align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)

    # 编号 / 出具时间
    meta_tbl = doc.add_table(rows=1, cols=2)
    meta_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_tbl.autofit = True
    for i, (k, v) in enumerate(block["meta"]):
        if i > 0:
            meta_tbl.add_row()
        c0, c1 = meta_tbl.rows[i].cells
        c0.width = Cm(3.6)
        c1.width = Cm(12.0)
        add_multiline(c0.paragraphs[0], k, size=9.5, color=(0x6B, 0x72, 0x80))
        add_multiline(c1.paragraphs[0], v, size=9.5)

    add_text("", size=6, space_after=0)

    # 章节
    for title, rows in block["sections"]:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(3)
        run = p.add_run(title)
        _docx_font(run, "黑体")
        run.font.size = Pt(12)
        run.bold = True
        run.font.color.rgb = RGBColor(0x12, 0x3A, 0x6E)
        # 章节下横线
        pPr = p._p.get_or_add_pPr()
        pbdr = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "8")
        bottom.set(qn("w:space"), "2")
        bottom.set(qn("w:color"), "123A6E")
        pbdr.append(bottom)
        pPr.append(pbdr)

        tbl = doc.add_table(rows=len(rows), cols=2)
        tbl.autofit = False
        set_borders(tbl)
        for i, (k, v) in enumerate(rows):
            c0, c1 = tbl.rows[i].cells
            c0.width = Cm(4.6)
            c1.width = Cm(11.0)
            shade(c0, "F4F6FA")
            add_multiline(c0.paragraphs[0], k, size=9.5, bold=True, color=(0x33, 0x3B, 0x4A))
            add_multiline(c1.paragraphs[0], v, size=9.5)

    # 结论框：True 蓝 / False 红 / None 橙（部分核验，内容一致性未核验）
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    ok = block.get("conclusion_ok")
    border, bg = ("2E5BBA", "EEF3FD") if ok is True else \
        (("B26B00", "FFF6E8") if ok is None else ("C0392B", "FDEEEE"))
    box = doc.add_table(rows=1, cols=1)
    set_borders(box, color=border, size=8)
    cell = box.rows[0].cells[0]
    shade(cell, bg)
    para = cell.paragraphs[0]
    r1 = para.add_run(block["conclusion_label"] + "：")
    _docx_font(r1, "黑体")
    r1.bold = True
    r1.font.size = Pt(10.5)
    r2 = para.add_run(block["conclusion"])
    _docx_font(r2)
    r2.font.size = Pt(10.5)

    # 声明
    if block.get("statement"):
        add_text("声明", size=11, bold=True, space_after=2)
        for line in block["statement"]:
            add_text(line, size=8.5, color=(0x4A, 0x53, 0x63), space_after=2)

    # 页脚
    footer = doc.sections[0].footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run(block["footer"])
    _docx_font(run)
    run.font.size = Pt(7.5)
    run.font.color.rgb = RGBColor(0x8A, 0x93, 0xA5)

    doc.save(path)
    return path


# ---------------------------------------------------------------- PDF

def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\n", "<br/>"))


def write_pdf(block: dict, path: str) -> str:
    block = _prepared(block)
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    font = _pdf_font()
    ink = colors.HexColor("#1F2430")
    muted = colors.HexColor("#6B7280")
    navy = colors.HexColor("#123A6E")

    st_title = ParagraphStyle("t", fontName=font, fontSize=18, leading=26,
                              alignment=TA_CENTER, textColor=ink)
    st_sub = ParagraphStyle("s", fontName=font, fontSize=8.5, leading=13,
                            alignment=TA_CENTER, textColor=muted)
    st_meta_k = ParagraphStyle("mk", fontName=font, fontSize=8.5, textColor=muted)
    st_meta_v = ParagraphStyle("mv", fontName=font, fontSize=9, textColor=ink, leading=13)
    st_h = ParagraphStyle("h", fontName=font, fontSize=11.5, leading=18, textColor=navy,
                          spaceBefore=10, spaceAfter=4)
    st_k = ParagraphStyle("k", fontName=font, fontSize=9, textColor=colors.HexColor("#333B4A"),
                          leading=13)
    st_v = ParagraphStyle("v", fontName=font, fontSize=9, textColor=ink, leading=13)
    st_box = ParagraphStyle("b", fontName=font, fontSize=9.5, textColor=ink, leading=15)
    st_small = ParagraphStyle("sm", fontName=font, fontSize=7.8, textColor=muted, leading=12)

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont(font, 7)
        canvas.setFillColor(muted)
        canvas.drawString(2.2 * cm, 1.1 * cm, block["footer"][:78])
        canvas.drawRightString(19.0 * cm, 1.1 * cm, "第 %d 页" % doc_.page)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=2.2 * cm, rightMargin=2.2 * cm,
        topMargin=1.9 * cm, bottomMargin=1.9 * cm,
        title=block["title"], author="信链",
    )

    story = [Paragraph(_esc(block["title"]), st_title),
             Paragraph(_esc(block["subtitle"]), st_sub),
             Spacer(1, 8)]

    meta_rows = [[Paragraph(_esc(k), st_meta_k), Paragraph(_esc(v), st_meta_v)]
                 for k, v in block["meta"]]
    meta = Table(meta_rows, colWidths=[3.4 * cm, 13.0 * cm])
    meta.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, colors.HexColor("#D9DEE7")),
    ]))
    story += [meta, Spacer(1, 4)]

    for title, rows in block["sections"]:
        body = [[Paragraph(_esc(title), st_h), ""]]
        body += [[Paragraph(_esc(k), st_k), Paragraph(_esc(v), st_v)] for k, v in rows]
        tbl = Table(body, colWidths=[4.4 * cm, 12.0 * cm], repeatRows=1)
        style = [
            ("SPAN", (0, 0), (-1, 0)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F4F6FA")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9DEE7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        tbl.setStyle(TableStyle(style))
        story.append(KeepTogether([tbl, Spacer(1, 6)]))

    ok = block.get("conclusion_ok")
    if ok is True:
        box_color, box_bg = colors.HexColor("#2E5BBA"), colors.HexColor("#EEF3FD")
    elif ok is None:
        box_color, box_bg = colors.HexColor("#B26B00"), colors.HexColor("#FFF6E8")
    else:
        box_color, box_bg = colors.HexColor("#C0392B"), colors.HexColor("#FDEEEE")
    concl = Table([[Paragraph(
        "<b>%s：</b>%s" % (_esc(block["conclusion_label"]), _esc(block["conclusion"])),
        st_box)]], colWidths=[16.4 * cm])
    concl.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1.0, box_color),
        ("BACKGROUND", (0, 0), (-1, -1), box_bg),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story += [Spacer(1, 4), concl]

    if block.get("statement"):
        story += [Spacer(1, 10), Paragraph(_esc("声明"), st_h)]
        for line in block["statement"]:
            story.append(Paragraph(_esc(line), st_small))
            story.append(Spacer(1, 3))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return path


# ---------------------------------------------------------------- 统一入口

def export(block: dict, path: str) -> str:
    """按扩展名写出 .docx 或 .pdf；其它扩展名抛 ValueError。"""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".docx":
        return write_docx(block, path)
    if ext == ".pdf":
        return write_pdf(block, path)
    raise ValueError("仅支持 .docx / .pdf，收到：%s" % ext)


def suggest_name(block: dict, ev_no: str) -> str:
    prefix = "存证凭证" if block.get("kind") == "receipt" else "证据报告"
    stamp = time.strftime("%Y%m%d")
    safe = re.sub(r"[^\w\-]", "_", (ev_no or "unknown")[:14])
    return "%s_%s_%s" % (prefix, safe, stamp)
