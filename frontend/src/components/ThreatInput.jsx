import React, { useState, useRef } from 'react';
import { Plus, X, Search, Image as ImageIcon, Loader2, Sparkles } from 'lucide-react';
import { createWorker } from 'tesseract.js';
import { useTranslation } from 'react-i18next';
import { detectInputType } from '../utils/detectType';

export const ThreatInput = ({ onAnalyze, loading }) => {
  const { t } = useTranslation();
  const [inputText, setInputText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [ocrLoading, setOcrLoading] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const [fileError, setFileError] = useState('');

  const fileInputRef = useRef(null);
  const inputType = detectInputType(inputText);

  const handleFileSelect = (file) => {
    setFileError('');
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setFileError('Please select a valid image file (PNG, JPG, WEBP).');
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      setFileError('Image file size must be under 5 MB.');
      return;
    }

    setSelectedFile(file);
    const objectUrl = URL.createObjectURL(file);
    setPreviewUrl(objectUrl);

    // Client-side OCR Fallback (Tesseract.js)
    runClientOcr(file);
  };

  const runClientOcr = async (file) => {
    try {
      setOcrLoading(true);
      const worker = await createWorker('eng');
      const ret = await worker.recognize(file);
      await worker.terminate();
      if (ret.data.text && ret.data.text.trim()) {
        setInputText((prev) => (prev ? `${prev}\n${ret.data.text.trim()}` : ret.data.text.trim()));
      }
    } catch (e) {
      console.warn('[Client OCR Warning]:', e);
    } finally {
      setOcrLoading(false);
    }
  };

  const removeFile = () => {
    setSelectedFile(null);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
    setFileError('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputText.trim() && !selectedFile) return;
    onAnalyze(inputText, selectedFile, inputType);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="relative group">
        <div
          className={`relative rounded-2xl bg-[var(--bg-input)] border border-[var(--border)] transition-all duration-300 shadow-[var(--shadow)] overflow-hidden ${
            isDragOver ? 'border-cyan-400 ring-2 ring-cyan-400/20' : 'hover:border-cyan-500/40'
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {/* Subtle Smart Input Detector Badge inside top-right corner */}
          {inputText.trim() && (
            <div className="absolute top-3 right-3 text-xs px-2.5 py-1 rounded-full bg-cyan-900/30 border border-cyan-700/30 text-cyan-300 flex items-center gap-1.5 shadow-sm font-semibold pointer-events-none z-20">
              {inputType === 'phone' ? '📱 Phone' : '🛡️ Threat'}
            </div>
          )}

          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste suspicious link, email, message or phone number..."
            spellCheck="false"
            rows={5}
            className="w-full min-h-[160px] p-5 pb-14 bg-transparent border-0 outline-none text-[var(--text-main)] placeholder-[var(--text-muted)] text-base leading-relaxed resize-y"
          />

          {/* Integrated Upload (+) & Attachment Bar at Bottom-Left */}
          <div className="absolute left-3 bottom-3 flex items-center space-x-3.5 z-20">
            <input
              type="file"
              ref={fileInputRef}
              accept="image/*"
              className="hidden"
              onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
            />

            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              title="Upload screenshot for OCR analysis"
              className="w-9 h-9 rounded-lg flex items-center justify-center text-slate-400 hover:text-white hover:bg-slate-800 transition-all duration-200"
            >
              <Plus className="w-5 h-5" />
            </button>

            {selectedFile && previewUrl && (
              <div className="relative group flex items-center">
                <div className="relative w-9 h-9 rounded-lg overflow-hidden border border-cyan-400/50 bg-slate-800 shadow-md">
                  <img
                    src={previewUrl}
                    alt="Screenshot preview"
                    className="w-full h-full object-cover"
                  />
                  {ocrLoading && (
                    <div className="absolute inset-0 bg-slate-950/70 flex items-center justify-center">
                      <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={removeFile}
                  title="Remove screenshot"
                  className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full bg-rose-500 hover:bg-rose-600 text-white flex items-center justify-center shadow-lg transition-transform hover:scale-110 z-30"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            )}
          </div>

          {/* Action Button at Bottom-Right */}
          <div className="absolute right-3 bottom-3 z-20">
            <button
              type="submit"
              disabled={loading || (!inputText.trim() && !selectedFile)}
              className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-cyan-200" />
                  <span>{inputType === 'phone' ? 'Lookup number' : 'Analyze threat'}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {fileError && (
        <p className="mt-2 text-xs text-rose-400 flex items-center space-x-1">
          <X className="w-3.5 h-3.5" />
          <span>{fileError}</span>
        </p>
      )}
    </div>
  );
};

export default ThreatInput;
