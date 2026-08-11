import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import ThreatInput from './components/ThreatInput';
import ThreatMeter from './components/ThreatMeter';
import ResultCard from './components/ResultCard';
import PhoneResultCard from './components/PhoneResultCard';
import UrlPreview from './components/UrlPreview';
import PreventionTips from './components/PreventionTips';
import DisclaimerBox from './components/DisclaimerBox';
import ExampleButtons from './components/ExampleButtons';
import ChatWidget from './components/ChatWidget';
import { ThemeProvider } from './context/ThemeContext';
import { useThreatAnalysis } from './hooks/useThreatAnalysis';
import { useTranslation } from 'react-i18next';
import { AlertCircle, RefreshCcw } from 'lucide-react';

function AppContent() {
  const { t } = useTranslation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { result, phoneResult, loading, error, runAnalysis, reset } = useThreatAnalysis();

  const handleSelectExample = (text) => {
    runAnalysis(text);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-main)] text-[var(--text-main)] selection:bg-cyan-500 selection:text-white transition-colors duration-300 relative overflow-x-hidden">
      
      {/* Faint Slow Spinning University Logo Watermark (z-0, pointer-events-none) */}
      <div className="bg-logo-watermark">
        <img
          src="/assets/logo-university.jpg"
          alt="Brainware University Logo Watermark"
          className="w-full h-full object-contain"
        />
      </div>

      {/* Optional Dark Backdrop Overlay when Sidebar is open (z-40) */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/40 backdrop-blur-[2px] z-40 transition-opacity duration-300"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Toggleable Sidebar (z-50) */}
      <Sidebar isOpen={sidebarOpen} setIsOpen={setSidebarOpen} />

      {/* Main Workspace Wrapper */}
      <div
        className="flex-1 flex flex-col min-h-screen transition-all duration-300 relative z-10"
        onClick={() => {
          if (sidebarOpen) {
            setSidebarOpen(false);
          }
        }}
      >
        {/* Top Header Navbar */}
        <Navbar sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} />

        {/* Main Container */}
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
          {/* Intro Section & Unified Main Input Box */}
          <section id="threat-input" className="space-y-4 max-w-4xl mx-auto text-center scroll-mt-24">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-xs font-semibold text-cyan-500">
              <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
              <span>Smart Unified Multimodal Threat & Telephony Detection Engine</span>
            </div>

            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[var(--text-main)]">
              {t('paste_title')}
            </h2>
            <p className="text-sm sm:text-base text-[var(--text-muted)] max-w-2xl mx-auto">
              {t('paste_sub')}
            </p>

            {/* Main Unified Input Component */}
            <div className="pt-4 text-left">
              <ThreatInput onAnalyze={runAnalysis} loading={loading} />
              <ExampleButtons onSelectExample={handleSelectExample} />
            </div>
          </section>

          {/* Error Display */}
          {error && (
            <div className="max-w-4xl mx-auto p-4 rounded-xl bg-rose-950/30 border border-rose-500/40 text-rose-300 text-sm flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
                <span>{error}</span>
              </div>
              <button
                onClick={reset}
                className="p-1 rounded hover:bg-rose-900/40 transition-colors"
                title="Dismiss error"
              >
                <RefreshCcw className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Phone Result Display Card */}
          {phoneResult && (
            <section className="pt-4">
              <PhoneResultCard result={phoneResult} />
            </section>
          )}

          {/* Phishing Threat Results Section */}
          {result && (
            <div className="space-y-8 animate-in fade-in slide-in-from-bottom-6 duration-500">
              {/* Threat Gauge & Result Breakdown */}
              <section className="max-w-6xl mx-auto space-y-8">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                  {/* Left Col: Threat Risk Gauge */}
                  <div className="lg:col-span-1">
                    <ThreatMeter score={result.score} riskLevel={result.risk_level} />
                  </div>

                  {/* Right Col: Detailed Analysis Cards */}
                  <div className="lg:col-span-2">
                    <ResultCard result={result} />
                  </div>
                </div>
              </section>

              {/* Dynamic Contextual Security Disclaimer Banner */}
              <section className="max-w-6xl mx-auto pt-2">
                <DisclaimerBox score={result.score} riskLevel={result.risk_level} />
              </section>

              {/* Dynamic Contextual Fraud Prevention Tips Grid */}
              <section className="max-w-6xl mx-auto pt-2">
                <PreventionTips
                  score={result.score}
                  riskLevel={result.risk_level}
                  attackType={result.attack_type}
                />
              </section>
            </div>
          )}

          {/* Cloud Sandbox URL Preview Section */}
          <section id="url-preview" className="max-w-4xl mx-auto pt-6 scroll-mt-24">
            <UrlPreview />
          </section>
        </main>

        {/* Floating Chatbot Assistant */}
        <ChatWidget />

        {/* Footer */}
        <footer className="border-t border-[var(--border)] bg-[var(--bg-sidebar)] py-6 text-center text-xs text-[var(--text-muted)] transition-colors">
          <p className="font-medium text-xs flex items-center justify-center gap-1.5 flex-wrap">
            <span>PhishGuard AI &middot; Engineered threat detection dashboard &middot;</span>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-lg bg-cyan-500/10 text-cyan-500 font-extrabold border border-cyan-500/20 shadow-sm">
              Developed by Team BYTE-BUILDERS
            </span>
          </p>
        </footer>
      </div>
    </div>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}

export default App;
