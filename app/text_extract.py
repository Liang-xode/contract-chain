# -*- coding: utf-8 -*-
"""
text_extract.py —— 从原始字节中抽取「正文节选」，供语义索引使用（路线 A）

隐私边界（硬约束）：
- 只在本机内存中解析 raw_content，抽取结果**绝不落库、绝不写入链状态**；
- 全文/密文/私钥都不外发；只有「节选」在用户开启 SEMANTIC_LLM_READS_CONTENT 时才会
  作为 Prompt 的一部分发给 LLM，且长度受 SEMANTIC_CONTENT_MAX_CHARS 限制；
- 解析失败一律返回空串，由上层降级为「文件名 + 元数据」索引，不中断存证主流程。
"""

import io
import re
import zipfile

_TEXT_EXTS = {
    "txt", "md", "markdown", "csv", "tsv", "log", "json", "xml", "html", "htm",
    "py", "java", "js", "ts", "c", "cpp", "h", "go", "rs", "sql", "yaml", "yml",
    "ini", "conf", "sh", "bat", "ps1",
}


def _clean(text: str) -> str:
    """压缩空白，去掉不可见字符，便于送 LLM。"""
    text = text.replace("\x00", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _decode(raw: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "gb18030", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return ""


def _extract_docx(raw: bytes) -> str:
    """优先用 python-docx；未安装时退化为 zip + OOXML 文本提取。"""
    try:
        from docx import Document
        doc = Document(io.BytesIO(raw))
        parts = [p.text for p in doc.paragraphs if p.text and p.text.strip()]
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text and cell.text.strip():
                        parts.append(cell.text)
        return "\n".join(parts)
    except Exception:
        pass
    # 零依赖兜底：docx 本质是 zip，正文在 word/document.xml 的 <w:t> 里
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            xml = z.read("word/document.xml").decode("utf-8", "ignore")
        texts = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, flags=re.S)
        return "\n".join(t for t in texts if t.strip())
    except Exception:
        return ""


def _extract_pdf(raw: bytes) -> str:
    """用 pypdf 抽取前若干页文本；不是真 PDF / 未安装 / 加密 PDF 时返回空串。"""
    # 先校验 PDF 魔数，避免对任意字节调用解析器产生大量告警
    if not raw.lstrip()[:5].startswith(b"%PDF"):
        return ""
    import logging
    try:
        from pypdf import PdfReader
        logging.getLogger("pypdf").setLevel(logging.CRITICAL)
        reader = PdfReader(io.BytesIO(raw))
        parts = []
        for page in reader.pages[:10]:          # 最多前 10 页，控制耗时
            try:
                parts.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(parts)
    except Exception:
        return ""


def _looks_textual(text: str) -> bool:
    """粗略判断解码结果是否像正常文本（避免二进制垃圾进入语义索引）。"""
    if not text:
        return False
    sample = text[:2000]
    printable = sum(1 for ch in sample if ch.isprintable() or ch in "\n\r\t")
    return len(sample) > 0 and (printable / len(sample)) > 0.85


def extract_text(filename: str, raw_content: bytes, max_chars: int = None) -> str:
    """按扩展名抽取正文节选。任何异常都返回空串（调用方据此降级）。"""
    if not raw_content:
        return ""
    from app import config
    limit = max_chars or config.SEMANTIC_CONTENT_MAX_CHARS
    name = (filename or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""

    try:
        if ext in _TEXT_EXTS:
            text = _decode(raw_content)
            if not text or not _looks_textual(text):
                return ""
        elif ext == "docx":
            text = _extract_docx(raw_content)
        elif ext == "pdf":
            text = _extract_pdf(raw_content)
        elif ext in ("xlsx", "xlsm"):
            # 表格类：不引新依赖，直接抽共享字符串表里的可读文本（尽力而为）
            text = _extract_xlsx(raw_content)
        else:
            # 未知类型：先尝试当文本解码；不像文本（二进制）则放弃，避免乱码进索引
            text = _decode(raw_content)
            if not text or not _looks_textual(text):
                return ""
    except Exception:
        return ""

    text = _clean(text)
    if not text:
        return ""
    return text[:limit]


def _extract_xlsx(raw: bytes) -> str:
    """零依赖抽取 xlsx 的 sharedStrings 文本（仅用于语义索引，非精确解析）。"""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = z.namelist()
            parts = []
            if "xl/sharedStrings.xml" in names:
                xml = z.read("xl/sharedStrings.xml").decode("utf-8", "ignore")
                parts = re.findall(r"<t[^>]*>(.*?)</t>", xml, flags=re.S)
            return "\n".join(p for p in parts if p.strip())
    except Exception:
        return ""
