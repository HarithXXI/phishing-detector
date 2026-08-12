import React from 'react';
import { Radio, AlertCircle } from 'lucide-react';

export const DnsCard = ({ dns = {} }) => {
  if (!dns) return null;

  const isApplicable = dns.is_applicable !== false && dns.status !== 'No domain to check';
  const risk = dns.risk ?? 0;
  const status = dns.status || (isApplicable ? 'Unknown' : 'No domain to check');

  if (!isApplicable) {
    return (
      <div className="p-5 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3 opacity-80">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Radio className="w-4 h-4 text-slate-400" />
            DNS Security & Mail Records
          </span>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-slate-700/50 text-slate-300 border border-slate-600/40">
            Text Analysis Only
          </span>
        </div>
        <p className="text-xs text-[var(--text-muted)] flex items-center gap-1.5">
          <AlertCircle className="w-3.5 h-3.5 text-slate-400" />
          No domain specified in input — DNS record check not applicable.
        </p>
      </div>
    );
  }

  const riskBadgeClass =
    risk >= 30
      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
      : risk >= 10
      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';

  return (
    <div className="p-5 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
          <Radio className="w-4 h-4 text-cyan-400" />
          DNS Security & Mail Records
        </span>
        <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${riskBadgeClass}`}>
          {status}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)]">
          <span className="text-[var(--text-muted)]">A Record:</span>
          {dns.A_valid ? (
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              ✓ Valid {dns.A?.[0] ? `(${dns.A[0]})` : ''}
            </span>
          ) : (
            <span className="text-rose-400 font-bold flex items-center gap-1">✗ Missing</span>
          )}
        </div>
        <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)]">
          <span className="text-[var(--text-muted)]">MX Server:</span>
          {dns.MX_valid ? (
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              ✓ Active {dns.MX?.[0] ? `(${dns.MX[0]})` : ''}
            </span>
          ) : (
            <span className="text-amber-400 font-bold flex items-center gap-1">○ None</span>
          )}
        </div>
        <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)]">
          <span className="text-[var(--text-muted)]">SPF Record:</span>
          {dns.SPF_pass ? (
            <span className="text-emerald-400 font-bold flex items-center gap-1">✓ Pass</span>
          ) : (
            <span className="text-amber-400 font-bold flex items-center gap-1">○ Missing</span>
          )}
        </div>
        <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)]">
          <span className="text-[var(--text-muted)]">DMARC:</span>
          {dns.DMARC_protected ? (
            <span className="text-emerald-400 font-bold flex items-center gap-1">✓ Protected</span>
          ) : (
            <span className="text-amber-400 font-bold flex items-center gap-1">○ Missing</span>
          )}
        </div>
      </div>
    </div>
  );
};

export default DnsCard;
