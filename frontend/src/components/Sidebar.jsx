import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  X,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Mail,
  MessageSquare,
  Phone,
  Globe,
  Share2,
  HelpCircle,
  ExternalLink
} from 'lucide-react';

const FRAUD_TYPES = [
  {
    id: 'email',
    title: 'Email',
    icon: Mail,
    iconColor: 'text-blue-500',
    bgColor: 'bg-blue-500/15 border-blue-500/20',
    desc: 'Report phishing emails, spoofed headers, and suspicious attachments.',
    guidance: 'Forward suspicious phishing emails directly to cybercrime.gov.in and report to your email provider.'
  },
  {
    id: 'sms',
    title: 'SMS',
    icon: MessageSquare,
    iconColor: 'text-emerald-500',
    bgColor: 'bg-emerald-500/15 border-emerald-500/20',
    desc: 'Report smishing SMS containing fake banking links or lottery scams.',
    guidance: 'Do not click links in SMS. Block sender and report on National Cyber Crime Portal.'
  },
  {
    id: 'phone',
    title: 'Phone Call',
    icon: Phone,
    iconColor: 'text-purple-500',
    bgColor: 'bg-purple-500/15 border-purple-500/20',
    desc: 'Report vishing calls impersonating bank officers or law enforcement.',
    guidance: 'Disconnect suspicious vishing calls. Never share OTPs or passwords over call.'
  },
  {
    id: 'website',
    title: 'Website',
    icon: Globe,
    iconColor: 'text-orange-500',
    bgColor: 'bg-orange-500/15 border-orange-500/20',
    desc: 'Report fake shopping websites, fake payment portals, or phishing URLs.',
    guidance: 'Report fake domain URLs to 1930 and submit URL on cybercrime.gov.in.'
  },
  {
    id: 'social',
    title: 'Social Media',
    icon: Share2,
    iconColor: 'text-pink-500',
    bgColor: 'bg-pink-500/15 border-pink-500/20',
    desc: 'Report fake social profiles, Telegram investment scams, or Instagram fraud.',
    guidance: 'Report fake account profiles on platform and file complaint on cybercrime.gov.in.'
  },
  {
    id: 'other',
    title: 'Other',
    icon: HelpCircle,
    iconColor: 'text-slate-400',
    bgColor: 'bg-slate-500/15 border-slate-500/20',
    desc: 'Report job offer scams, task-based scams, or general cyber fraud.',
    guidance: 'Gather transaction receipts, chat screenshots, and report immediately.'
  }
];

export default function Sidebar({ isOpen, setIsOpen }) {
  const { t } = useTranslation();
  const [isReportOpen, setIsReportOpen] = useState(true);
  const [selectedFraud, setSelectedFraud] = useState(null);

  // Close on ESC key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, setIsOpen]);

  const handleCardClick = (e, fraud) => {
    e.stopPropagation();
    setSelectedFraud(fraud);
  };

  return (
    <>
      {/* Toggleable Sidebar Container - Uses CSS Custom Variables */}
      <aside
        onClick={(e) => e.stopPropagation()}
        className={`fixed top-0 left-0 bottom-0 h-screen w-[280px] bg-[var(--bg-sidebar)] backdrop-blur-xl border-r border-[var(--border)] text-[var(--text-main)] z-50 transition-transform duration-300 ease-in-out shadow-2xl flex flex-col ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Sidebar Top Header */}
        <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-md">
              <Shield className="w-4.5 h-4.5 text-white" />
            </div>
            <span className="font-bold text-[var(--text-main)] tracking-wide text-base">PhishGuard</span>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse mr-1" />
              LIVE
            </span>
          </div>

          {/* Close button X */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsOpen(false);
            }}
            className="w-8 h-8 rounded-lg bg-[var(--bg-card)] border border-[var(--border)] flex items-center justify-center text-[var(--text-muted)] hover:text-[var(--text-main)] transition-colors"
            title="Close sidebar"
            aria-label="Close sidebar"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Sidebar Scrollable Body Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {/* Section 1: "Report a Fraud" Accordion Toggle Button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsReportOpen(!isReportOpen);
            }}
            className="w-full bg-[var(--bg-card)] hover:bg-[var(--bg-main)] border border-[var(--border)] rounded-xl p-3.5 flex items-center justify-between transition-colors group cursor-pointer shadow-sm"
            aria-expanded={isReportOpen}
          >
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-4.5 h-4.5 text-amber-500" />
              </div>
              <span className="text-sm font-semibold text-[var(--text-main)] group-hover:text-amber-500 transition-colors">
                Report a Fraud
              </span>
            </div>

            {isReportOpen ? (
              <ChevronUp className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--text-main)] transition-colors" />
            ) : (
              <ChevronDown className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--text-main)] transition-colors" />
            )}
          </button>

          {/* Section 2: 6 Fraud Category Cards Grid (3 Columns) */}
          {isReportOpen && (
            <div className="grid grid-cols-3 gap-2.5 pt-1 animate-in fade-in duration-200">
              {FRAUD_TYPES.map((fraud) => {
                const Icon = fraud.icon;
                const translatedTitle = t(`sidebar_${fraud.id}`) || fraud.title;
                return (
                  <button
                    key={fraud.id}
                    onClick={(e) => handleCardClick(e, { ...fraud, title: translatedTitle })}
                    className="bg-[var(--bg-card)] hover:bg-[var(--bg-main)] border border-[var(--border)] hover:border-cyan-500/40 rounded-xl p-3 flex flex-col items-center justify-center gap-2 transition-all cursor-pointer group text-center shadow-sm hover:shadow-md hover:-translate-y-0.5"
                    title={`Report ${translatedTitle} Fraud`}
                  >
                    <div className={`w-10 h-10 rounded-xl ${fraud.bgColor} border flex items-center justify-center transition-transform group-hover:scale-110`}>
                      <Icon className={`w-5 h-5 ${fraud.iconColor}`} />
                    </div>
                    <span className="text-[11px] font-medium text-[var(--text-main)] group-hover:text-cyan-500 leading-tight">
                      {translatedTitle}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Sidebar Bottom Fixed Footer */}
        <div className="p-4 border-t border-[var(--border)] mt-auto bg-[var(--bg-sidebar)]">
          <p className="text-[11px] text-[var(--text-muted)]">
            Official:{' '}
            <a
              href="https://cybercrime.gov.in/login"
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="text-cyan-500 hover:underline font-semibold"
            >
              cybercrime.gov.in
            </a>{' '}
            | <span className="text-amber-500 font-bold">1930</span>
          </p>
        </div>
      </aside>

      {/* Fraud Report Guidance Modal */}
      {selectedFraud && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center p-4"
          onClick={(e) => e.stopPropagation()}
        >
          <div
            className="bg-[var(--bg-sidebar)] border border-[var(--border)] text-[var(--text-main)] rounded-2xl max-w-md w-full p-6 shadow-2xl relative animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
              <div className="flex items-center space-x-3">
                <div className={`w-9 h-9 rounded-xl ${selectedFraud.bgColor} border flex items-center justify-center`}>
                  <selectedFraud.icon className={`w-5 h-5 ${selectedFraud.iconColor}`} />
                </div>
                <h3 className="text-base font-bold text-[var(--text-main)]">Report {selectedFraud.title} Fraud</h3>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFraud(null);
                }}
                className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-main)] hover:bg-[var(--bg-card)]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 space-y-3">
              <p className="text-xs text-[var(--text-muted)] leading-relaxed">
                {selectedFraud.desc}
              </p>
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-600 dark:text-amber-200 text-xs leading-relaxed">
                <strong className="text-amber-500 block mb-1">🚨 Recommended Action:</strong>
                {selectedFraud.guidance}
              </div>
            </div>

            <div className="pt-4 border-t border-[var(--border)] flex items-center justify-end space-x-3">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFraud(null);
                }}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-[var(--bg-card)] hover:bg-[var(--bg-main)] text-[var(--text-main)] border border-[var(--border)] transition-colors"
              >
                Cancel
              </button>
              <a
                href="https://cybercrime.gov.in/login"
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 flex items-center space-x-1.5 transition-colors shadow-lg shadow-amber-500/20"
              >
                <span>Proceed to CyberCrime Portal</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
