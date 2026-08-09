/**
 * PhishGuard AI — Integrated Inline Photo Upload (+ Button) & Client-Side OCR Engine (Tesseract.js v5)
 * Allows users to upload screenshots via a sleek + button inside the main text box or by dragging & dropping onto the text area.
 */

(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", () => {
        const btnAddPhoto = document.getElementById("btn-add-photo");
        const photoInput = document.getElementById("photo-input");
        const textareaWrap = document.getElementById("textarea-wrap");
        const inputText = document.getElementById("input-text");
        
        const inlinePreview = document.getElementById("inline-photo-preview");
        const inlineImgThumb = document.getElementById("inline-img-thumb");
        const inlinePhotoName = document.getElementById("inline-photo-name");
        const inlineOcrProgress = document.getElementById("inline-ocr-progress");
        const inlineOcrStatus = document.getElementById("inline-ocr-status");
        const btnRemoveInlinePhoto = document.getElementById("btn-remove-inline-photo");

        if (!photoInput || !inputText) return;

        // Forward container clicks to focus text area
        textareaWrap?.addEventListener("click", (e) => {
            if (!e.target.closest("#btn-add-photo") && !e.target.closest("#btn-remove-inline-photo") && e.target !== inputText) {
                inputText.focus();
            }
        });

        // 1. Click + Button trigger
        btnAddPhoto?.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            photoInput.click();
        });

        photoInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleImageFile(e.target.files[0]);
            }
        });

        btnRemoveInlinePhoto?.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            resetInlinePhoto();
        });

        // 2. Drag & Drop on Text Area Container
        const dragTarget = textareaWrap || inputText;
        if (dragTarget) {
            ["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => {
                dragTarget.addEventListener(evt, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                }, false);
            });

            ["dragenter", "dragover"].forEach((evt) => {
                dragTarget.addEventListener(evt, () => textareaWrap?.classList.add("dragover"), false);
            });

            ["dragleave", "drop"].forEach((evt) => {
                dragTarget.addEventListener(evt, () => textareaWrap?.classList.remove("dragover"), false);
            });

            dragTarget.addEventListener("drop", (e) => {
                const dt = e.dataTransfer;
                if (dt.files && dt.files.length > 0) {
                    const file = dt.files[0];
                    if (file.type.startsWith("image/")) {
                        handleImageFile(file);
                    }
                }
            });
        }

        // 3. Process File & Run OCR
        function handleImageFile(file) {
            if (!file.type.startsWith("image/")) {
                alert("Please select a valid image screenshot (PNG, JPG, WebP).");
                return;
            }

            if (file.size > 5 * 1024 * 1024) {
                alert("File size exceeds 5MB limit. Please select a smaller screenshot.");
                return;
            }

            const reader = new FileReader();
            reader.onload = function (evt) {
                const dataUrl = evt.target.result;
                
                // Show inline preview bar
                inlineImgThumb.src = dataUrl;
                inlinePhotoName.textContent = file.name || "screenshot.png";
                inlinePreview.classList.remove("hidden");
                inlineOcrProgress.classList.remove("hidden");
                inlineOcrStatus.textContent = "Reading text...";

                // Start Tesseract.js OCR
                runTesseractOCR(dataUrl, file);
            };
            reader.readAsDataURL(file);
        }

        // 4. Client-side OCR via Tesseract.js
        async function runTesseractOCR(dataUrl, originalFile) {
            try {
                if (typeof Tesseract === "undefined") {
                    throw new Error("Tesseract.js CDN script not loaded");
                }

                const worker = await Tesseract.createWorker("eng", 1, {
                    logger: (m) => {
                        if (m.status === "recognizing text") {
                            const pct = Math.round((m.progress || 0) * 100);
                            inlineOcrStatus.textContent = `${pct}%`;
                        } else if (m.status === "loading tesseract core") {
                            inlineOcrStatus.textContent = "Loading...";
                        }
                    },
                });

                const ret = await worker.recognize(dataUrl);
                await worker.terminate();

                const extracted = (ret.data.text || "").trim();

                if (extracted.length >= 3) {
                    onOCRComplete(extracted);
                } else {
                    console.warn("[PhotoScan] Low OCR output, attempting backend vision API fallback...");
                    await tryBackendVisionFallback(originalFile, dataUrl);
                }
            } catch (err) {
                console.error("[PhotoScan] Client-side OCR error:", err);
                await tryBackendVisionFallback(originalFile, dataUrl);
            }
        }

        // 5. Vision API Fallback
        async function tryBackendVisionFallback(file, dataUrl) {
            inlineOcrStatus.textContent = "Consulting AI Vision...";

            try {
                const formData = new FormData();
                formData.append("image", file);
                formData.append("image_base64", dataUrl);

                const API_BASE = window.API_BASE || "";
                const resp = await fetch(`${API_BASE}/api/analyze-image`, {
                    method: "POST",
                    body: formData,
                });

                if (resp.ok) {
                    const data = await resp.json();
                    const text = data.extracted_text || data.text || "";
                    if (text.length >= 3) {
                        onOCRComplete(text);
                        return;
                    }
                }
            } catch (fallbackErr) {
                console.warn("[PhotoScan] Backend vision fallback error:", fallbackErr);
            }

            inlineOcrStatus.textContent = "No text found";
            setTimeout(() => inlineOcrProgress.classList.add("hidden"), 1500);
        }

        function onOCRComplete(extractedText) {
            inputText.value = extractedText;
            inlineOcrStatus.textContent = "Text extracted!";
            setTimeout(() => inlineOcrProgress.classList.add("hidden"), 1500);

            if (typeof window.showToast === "function") {
                window.showToast("Text extracted into text box!");
            }
        }

        function resetInlinePhoto() {
            photoInput.value = "";
            inlineImgThumb.src = "";
            inlinePhotoName.textContent = "";
            inlinePreview.classList.add("hidden");
            inlineOcrProgress.classList.add("hidden");
        }
    });
})();
