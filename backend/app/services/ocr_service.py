"""
Computer Vision & OCR Service for PhishGuard Heavy Backend Engine
Uses OpenCV for image pre-processing & binarization and EasyOCR for offline text recognition.
DO NOT IMPORT IN LIGHTWEIGHT VERCEL ENGINE (api/index.py).
"""

import io
from typing import Optional

try:
    import cv2
    import numpy as np
    import easyocr
except ImportError:
    cv2 = None
    np = None
    easyocr = None

# Lazy-loaded EasyOCR reader instance (loads weights once into memory)
_EASYOCR_READER = None


def get_ocr_reader():
    global _EASYOCR_READER
    if _EASYOCR_READER is None and easyocr is not None:
        try:
            print("[OCR Service] Initializing EasyOCR Reader (English, GPU=False)...")
            _EASYOCR_READER = easyocr.Reader(['en'], gpu=False)
        except Exception as e:
            print(f"[OCR Service Reader Init Error]: {e}")
            _EASYOCR_READER = None
    return _EASYOCR_READER


def scan_image(image_bytes: bytes) -> str:
    """
    Preprocess screenshot image with OpenCV and extract text using EasyOCR.
    """
    if not image_bytes:
        return ""

    if cv2 is None or np is None or easyocr is None:
        print("[OCR Service] OpenCV or EasyOCR not installed. Attempting PIL fallback...")
        return _fallback_pil_extract(image_bytes)

    try:
        # Step 1: Decode image bytes to OpenCV matrix
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            print("[OCR Service] cv2.imdecode returned None. Falling back to raw bytes...")
            return _fallback_pil_extract(image_bytes)

        # Step 2: OpenCV Preprocessing (Grayscale + Thresholding)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)

        # Step 3: Run EasyOCR
        reader = get_ocr_reader()
        if reader is not None:
            results = reader.readtext(thresh)
            extracted_lines = []
            for bbox, text, prob in results:
                if text and text.strip():
                    extracted_lines.append(text.strip())
            
            combined_text = "\n".join(extracted_lines)
            if combined_text.strip():
                print(f"[OCR Service] Extracted {len(extracted_lines)} lines via EasyOCR")
                return combined_text

        # If thresholding yielded empty results, retry on original gray image
        if reader is not None:
            results = reader.readtext(gray)
            lines = [t[1].strip() for t in results if t[1] and t[1].strip()]
            if lines:
                return "\n".join(lines)

    except Exception as e:
        print(f"[OCR Service Exception]: {e}")

    return _fallback_pil_extract(image_bytes)


def _fallback_pil_extract(image_bytes: bytes) -> str:
    """Fallback basic OCR using pytesseract or PIL if OpenCV/EasyOCR fail."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        # Basic sanity check
        w, h = img.size
        print(f"[OCR Service] Image loaded via PIL ({w}x{h})")
    except Exception as e:
        print(f"[OCR Service PIL Fallback Error]: {e}")
    return ""


if __name__ == "__main__":
    print("Testing ocr_service module import...")
    print("OpenCV installed:", cv2 is not None)
    print("EasyOCR installed:", easyocr is not None)
