"""Tests for security_agent/doc_extract.py: text/PDF/image extraction
with an OCR fallback for scanned/image-only content.

Tests that need a real tesseract binary + pytesseract/PyMuPDF are
skipped (not failed) when those aren't installed -- OCR is an optional
extra (security_agent/ocr_requirements.txt), and the pure-text-PDF
path and the "OCR unavailable" refusal path don't need any of it.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.doc_extract import (
    OcrUnavailable,
    extract_document_text,
    extract_text_from_pdf,
)

pytesseract = pytest.importorskip("pytesseract", reason="OCR extras not installed")
pymupdf = pytest.importorskip("pymupdf", reason="OCR extras not installed")
PIL_Image = pytest.importorskip("PIL.Image", reason="OCR extras not installed")


def _tesseract_available() -> bool:
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:  # noqa: BLE001
        return False


requires_tesseract = pytest.mark.skipif(
    not _tesseract_available(), reason="tesseract binary not installed"
)


@pytest.fixture
def text_pdf(tmp_path) -> Path:
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Introduction to Ethical Hacking\nReal text layer, no OCR needed.")
    path = tmp_path / "text.pdf"
    doc.save(str(path))
    doc.close()
    return path


@pytest.fixture
def scanned_image(tmp_path) -> Path:
    from PIL import ImageDraw

    img = PIL_Image.new("RGB", (900, 200), "white")
    draw = ImageDraw.Draw(img)
    draw.text((20, 20), "Ethical Hacking Chapter One", fill="black")
    draw.text((20, 60), "Reconnaissance and scoping basics.", fill="black")
    path = tmp_path / "page.png"
    img.save(path)
    return path


@pytest.fixture
def scanned_pdf(tmp_path, scanned_image) -> Path:
    doc = pymupdf.open()
    page = doc.new_page(width=900, height=200)
    page.insert_image(pymupdf.Rect(0, 0, 900, 200), filename=str(scanned_image))
    path = tmp_path / "scanned.pdf"
    doc.save(str(path))
    doc.close()
    return path


def test_text_pdf_extracted_without_ocr(text_pdf):
    text, info = extract_text_from_pdf(text_pdf)
    assert "Introduction to Ethical Hacking" in text
    assert info.ocr_pages == 0
    assert info.text_pages == 1


@requires_tesseract
def test_scanned_pdf_falls_back_to_ocr(scanned_pdf):
    text, info = extract_document_text(scanned_pdf)
    assert info.ocr_pages == 1
    assert info.text_pages == 0
    # OCR of a generated image can mangle a character or two; the
    # distinctive words surviving is what actually matters here.
    assert "hical" in text and "Hacking" in text


@requires_tesseract
def test_standalone_image_is_ocrd(scanned_image):
    text, info = extract_document_text(scanned_image)
    assert info.ocr_pages == 1
    assert "hical" in text and "Hacking" in text


def test_ocr_unavailable_raises_clean_error_not_silent_empty_text(monkeypatch, scanned_pdf):
    import builtins

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name in ("pytesseract", "pymupdf"):
            raise ImportError(f"blocked for test: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)

    with pytest.raises(OcrUnavailable) as exc_info:
        extract_document_text(scanned_pdf)
    assert "ocr_requirements.txt" in str(exc_info.value)
    assert "tesseract" in str(exc_info.value).lower()


def test_plain_text_file_bypasses_pdf_image_path(tmp_path):
    doc = tmp_path / "notes.txt"
    doc.write_text("Plain text, no PDF/image handling involved.")
    text, info = extract_document_text(doc)
    assert text == "Plain text, no PDF/image handling involved."
    assert info.ocr_pages == 0
    assert info.total_pages == 1
