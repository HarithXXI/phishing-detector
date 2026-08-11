"""
Computer Vision & OCR Service for PhishGuard Heavy Backend Engine
Uses EasyOCR and OpenCV for image pre-processing & robust offline text recognition.
DO NOT IMPORT IN LIGHTWEIGHT VERCEL ENGINE (api/index.py).
"""

import io
from typing import Optional

# Safe individual imports
try:
    import numpy as np
except Exception:
    np = None

try:
    import cv2
except Exception:
    cv2 = None

try:
    import easyocr
except Exception:
    easyocr = None

# Lazy-loaded EasyOCR reader instance (loads weights once into memory with verbose=False)
_EASYOCR_READER = None


def get_ocr_reader():
    global _EASYOCR_READER
    if _EASYOCR_READER is None and easyocr is not None:
        try:
            print("[OCR Service] Initializing EasyOCR Reader (English, GPU=False, Verbose=False)...")
            _EASYOCR_READER = easyocr.Reader(['en'], gpu=False, verbose=False)
            print("[OCR Service] EasyOCR Reader initialized successfully!")
        except Exception as e:
            print(f"[OCR Service Reader Init Error]: {e}")
            _EASYOCR_READER = None
    return _EASYOCR_READER


def scan_image(image_bytes: bytes) -> str:
    """
    Preprocess screenshot image and extract text using EasyOCR offline engine.
    """
    if not image_bytes:
        return ""

    reader = get_ocr_reader()
    if reader is None:
        print("[OCR Service] EasyOCR unavailable. Returning empty string for fallback...")
        return ""

    try:
        # Method 1: Pass raw byte stream directly to EasyOCR
        results = reader.readtext(image_bytes)
        lines = [text.strip() for bbox, text, prob in results if text and text.strip()]
        if lines:
            combined = "\n".join(lines)
            print(f"[OCR Service] Extracted {len(lines)} lines directly via EasyOCR byte stream")
            return combined

        # Method 2: Decode with OpenCV and retry on RGB matrix if byte stream yielded no bounding boxes
        if cv2 is not None and np is not None:
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is not None:
                rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                results_rgb = reader.readtext(rgb)
                lines_rgb = [text.strip() for bbox, text, prob in results_rgb if text and text.strip()]
                if lines_rgb:
                    print(f"[OCR Service] Extracted {len(lines_rgb)} lines via OpenCV RGB matrix")
                    return "\n".join(lines_rgb)

    except Exception as e:
        print(f"[OCR Service Exception]: {e}")

    return ""
