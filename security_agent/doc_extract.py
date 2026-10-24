"""Text extraction for `learning.py`'s learn_from_document path, including
OCR for scanned/image-only PDF pages and plain image files.

Local, read-only, no network target -- this stays in the "reading is
never gated" category the rest of learning.py already relies on. PDF
parsing (pypdf) is a base dependency since it needs no system binary;
OCR (pytesseract + PyMuPDF) is an opt-in extra -- see
security_agent/ocr_requirements.txt -- because it also needs the
tesseract-ocr system package. Both are imported lazily here so a
PDF/image that doesn't need OCR, or a plain text file, never requires
OCR's extra dependencies at all.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pypdf

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".gif", ".webp"}

# Below this many characters, a PDF page's embedded text is treated as
# absent/noise (a scanned page with no real text layer, or a bad OCR
# layer already baked into the file) and re-extracted via OCR instead.
MIN_CHARS_PER_PAGE = 40

# Render resolution for OCR -- high enough for normal document text,
# not so high it makes OCR slow on long scanned documents.
OCR_DPI = 200


class OcrUnavailable(RuntimeError):
    """OCR was needed (an image-only PDF page, or an image file) but
    pytesseract/PyMuPDF aren't installed, or the tesseract binary isn't
    on PATH."""


@dataclass
class ExtractionInfo:
    total_pages: int
    ocr_pages: int
    text_pages: int


def _ocr_deps():
    try:
        import pytesseract
        from PIL import Image
    except ImportError as exc:
        raise OcrUnavailable(
            "OCR needed but not installed. Run: "
            "pip install -r security_agent/ocr_requirements.txt "
            "-- and install the tesseract-ocr system package "
            "(e.g. `apt install tesseract-ocr`, `brew install tesseract`, "
            "or see https://github.com/tesseract-ocr/tesseract)."
        ) from exc
    try:
        pytesseract.get_tesseract_version()
    except Exception as exc:  # noqa: BLE001
        raise OcrUnavailable(
            "pytesseract is installed but the tesseract binary isn't on "
            "PATH. Install the tesseract-ocr system package."
        ) from exc
    return pytesseract, Image


def extract_text_from_image(path: Path) -> tuple[str, ExtractionInfo]:
    pytesseract, Image = _ocr_deps()
    with Image.open(path) as img:
        text = pytesseract.image_to_string(img)
    return text, ExtractionInfo(total_pages=1, ocr_pages=1, text_pages=0)


def extract_text_from_pdf(path: Path) -> tuple[str, ExtractionInfo]:
    reader = pypdf.PdfReader(str(path))
    total_pages = len(reader.pages)
    page_texts: list[str] = []
    ocr_pages = 0
    text_pages = 0
    ocr_doc = None  # pymupdf doc, opened lazily only if some page needs it
    ocr_unavailable_reason: str | None = None

    for i, page in enumerate(reader.pages):
        extracted = (page.extract_text() or "").strip()
        if len(extracted) >= MIN_CHARS_PER_PAGE:
            page_texts.append(extracted)
            text_pages += 1
            continue

        if ocr_unavailable_reason is not None:
            # Already know OCR isn't available this run -- don't retry
            # per page, just keep whatever sparse text pypdf found.
            page_texts.append(extracted)
            continue

        try:
            pytesseract, Image = _ocr_deps()
            import pymupdf

            if ocr_doc is None:
                ocr_doc = pymupdf.open(str(path))
            zoom = OCR_DPI / 72
            pix = ocr_doc[i].get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            ocr_text = pytesseract.image_to_string(img).strip()
            page_texts.append(ocr_text)
            ocr_pages += 1
        except OcrUnavailable as exc:
            ocr_unavailable_reason = str(exc)
            page_texts.append(extracted)

    if ocr_doc is not None:
        ocr_doc.close()

    text = "\n\n".join(t for t in page_texts if t)
    info = ExtractionInfo(total_pages=total_pages, ocr_pages=ocr_pages, text_pages=text_pages)
    # Surface the OCR-unavailable reason only if it actually mattered
    # (some page needed it and got nothing usable out of pypdf either).
    if ocr_unavailable_reason and not text.strip():
        raise OcrUnavailable(ocr_unavailable_reason)
    return text, info


def extract_document_text(path: Path) -> tuple[str, ExtractionInfo]:
    """Dispatches on file type. Raises OcrUnavailable if OCR was the
    only way to get usable text and isn't installed; raises
    UnicodeDecodeError for a binary file that's neither a recognized
    PDF nor an image (caller decides how to report that).
    """
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract_text_from_pdf(path)
    if suffix in IMAGE_SUFFIXES:
        return extract_text_from_image(path)

    text = path.read_text(encoding="utf-8")
    return text, ExtractionInfo(total_pages=1, ocr_pages=0, text_pages=1)
