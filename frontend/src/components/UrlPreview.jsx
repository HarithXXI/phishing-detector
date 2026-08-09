import React, { useState } from 'react';
import { Globe, RefreshCw, ShieldCheck, X, Camera, Zap } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { fetchScreenshot, fetchUrlPreview } from '../services/api';

export const UrlPreview = () => {
  const { t } = useTranslation();
  const [urlInput, setUrlInput] = useState('');
  const [screenshotData, setScreenshotData] = useState(null);
  const [previewFallback, setPreviewFallback] = useState(null);
  const [loading, setLoading] = useState(false);
  const [statusText, setStatusText] = useState('');

  const handlePreviewSubmit = async (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    setLoading(true);
    setStatusText('Taking screenshot with isolated browser...');
    setScreenshotData(null);
    setPreviewFallback(null);

    try {
      const data = await fetchUrlPreview(urlInput.trim());
      setPreviewFallback(data);
    } catch (err) {
      console.error('[UrlPreview Error]:', err);
    } finally {
      setLoading(false);
      setStatusText('');
    }
  };

  const clearPreview = () => {
    setScreenshotData(null);
    setPreviewFallback(null);
    setUrlInput('');
  };

  return (
    <div className="w-full bg-[var(--bg-card)] border border-[var(--border)] rounded-2xl p-6 shadow-sm backdrop-blur-md transition-all duration-300">
      <div className="flex items-center justify-between pb-4 mb-4 border-b border-[var(--border)]">
        <div className="flex items-center space-x-2">
          <Globe className="w-5 h-5 text-cyan-500" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-[var(--text-main)]">
            {t('url_preview')}
          </h3>
        </div>
        {(screenshotData || previewFallback) && (
          <button
            onClick={clearPreview}
            className="text-xs text-[var(--text-muted)] hover:text-[var(--text-main)] flex items-center gap-1 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
            <span>Clear Preview</span>
          </button>
        )}
      </div>

      <form onSubmit={handlePreviewSubmit} className="flex gap-2">
        <input
          type="text"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="Paste ANY website URL (e.g. https://paypal.com or https://google.com)..."
          className="flex-1 px-4 py-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)] text-sm text-[var(--text-main)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500 transition-all"
        />
        <button
          type="submit"
          disabled={loading || !urlInput.trim()}
          className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs flex items-center space-x-1.5 disabled:opacity-50 transition-all shadow-md cursor-pointer"
        >
          {loading ? <RefreshCw className="w-4 h-4 animate-spin text-white" /> : <Camera className="w-4 h-4 text-cyan-200" />}
          <span>{loading ? 'Capturing...' : 'Capture Screenshot'}</span>
        </button>
      </form>

      {/* Loading Status Notice */}
      {loading && (
        <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-xs text-cyan-500 flex items-center space-x-2">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-500" />
          <span>{statusText || 'Taking screenshot with isolated browser...'}</span>
        </div>
      )}

      {/* Render Playwright Screenshot Frame */}
      {screenshotData && screenshotData.screenshot && (
        <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--bg-main)] overflow-hidden space-y-2 p-3">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] px-1 border-b border-[var(--border)] pb-2">
            <span className="truncate max-w-[70%] font-mono text-cyan-500">{screenshotData.url}</span>
            <div className="flex items-center space-x-2">
              {screenshotData.cached && (
                <span className="flex items-center gap-1 text-[10px] font-bold text-cyan-500 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  <Zap className="w-3 h-3 text-cyan-500" /> 24h SQLite Cache Hit
                </span>
              )}
              <span className="flex items-center gap-1 text-emerald-500 font-semibold">
                <ShieldCheck className="w-3.5 h-3.5" /> Isolated Sandbox
              </span>
            </div>
          </div>

          <div className="relative w-full aspect-video rounded-lg overflow-hidden bg-slate-900 flex items-center justify-center border border-[var(--border)]">
            <img
              src={screenshotData.screenshot}
              alt="Live Website Sandbox Screenshot"
              className="w-full h-full object-cover"
            />
          </div>
        </div>
      )}

      {/* Fallback Metadata Frame */}
      {previewFallback && !screenshotData && (
        <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--bg-main)] overflow-hidden space-y-2 p-3">
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] px-1 border-b border-[var(--border)] pb-2">
            <span className="truncate max-w-[80%] font-mono text-cyan-500">{previewFallback.final_url || previewFallback.original_url}</span>
            <span className="flex items-center gap-1 text-amber-500 font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" /> Metadata Fallback
            </span>
          </div>

          <div className="relative w-full aspect-video rounded-lg overflow-hidden bg-slate-900 flex items-center justify-center border border-[var(--border)]">
            <img
              src={previewFallback.screenshot || previewFallback.screenshot_url || '/assets/no-preview.png'}
              alt="Website Sandbox Screenshot"
              className="w-full h-full object-cover"
              onError={(e) => {
                e.target.onerror = null;
                e.target.src = '/assets/no-preview.png';
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default UrlPreview;
