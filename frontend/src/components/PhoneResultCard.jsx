import React from 'react';
import { Phone, Globe, Radio, AlertTriangle, CheckCircle, ShieldAlert, Clock } from 'lucide-react';

export const PhoneResultCard = ({ result }) => {
  if (!result) return null;

  if (result.error) {
    return (
      <div className="w-full max-w-4xl mx-auto p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-sm flex items-center space-x-2">
        <AlertTriangle className="w-5 h-5 shrink-0" />
        <span>{result.error}</span>
      </div>
    );
  }

  const isVoip = result.is_voip;
  const isHighRisk = result.risk >= 30 || isVoip;

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-6 duration-500">
      {/* Top Banner */}
      <div
        className={`p-6 rounded-2xl border transition-all duration-300 ${
          isHighRisk
            ? 'border-rose-500/40 bg-rose-500/10 text-rose-300 shadow-xl'
            : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300 shadow-xl'
        }`}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${
                isHighRisk ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}
            >
              {isHighRisk ? <ShieldAlert className="w-7 h-7" /> : <Phone className="w-7 h-7" />}
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-lg font-bold text-[var(--text-main)] font-mono">
                  {result.international || result.number}
                </h3>
                {isVoip && (
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                    ⚠️ VoIP Number
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                Caller-ID + numint OSINT Telephony Analysis
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span
              className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                isHighRisk
                  ? 'bg-rose-500/20 text-rose-500 border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-500 border-emerald-500/40'
              }`}
            >
              {isHighRisk ? 'HIGH' : 'LOW'} RISK ({result.risk || 0}%)
            </span>
          </div>
        </div>
      </div>

      {/* Grid of OSINT Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Country */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Globe className="w-4 h-4 text-cyan-400" />
            Country & Code
          </span>
          <p className="text-sm font-bold text-[var(--text-main)]">
            {result.country || 'Unknown'} (+{result.country_code || 'N/A'})
          </p>
        </div>

        {/* Carrier */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Radio className="w-4 h-4 text-blue-400" />
            Carrier Operator
          </span>
          <p className="text-sm font-bold text-[var(--text-main)]">
            {result.carrier || 'Unknown'}
          </p>
        </div>

        {/* Line Type */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Phone className="w-4 h-4 text-purple-400" />
            Line Type
          </span>
          <p className={`text-sm font-bold ${isVoip ? 'text-rose-400' : 'text-emerald-400'}`}>
            {result.line_type || 'UNKNOWN'}
          </p>
        </div>

        {/* Validation Status */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            {result.is_valid ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-400" />}
            Validation
          </span>
          <p className={`text-sm font-bold ${result.is_valid ? 'text-emerald-400' : 'text-rose-400'}`}>
            {result.is_valid ? 'Valid Number' : 'Invalid Number'}
          </p>
        </div>

        {/* Timezone */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-amber-400" />
            Timezone
          </span>
          <p className="text-sm font-bold text-[var(--text-main)] truncate">
            {result.timezones?.length ? result.timezones.join(', ') : 'Unknown'}
          </p>
        </div>

        {/* National Format */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)]">
            National Format
          </span>
          <p className="text-sm font-mono font-bold text-[var(--text-main)]">
            {result.national || 'N/A'}
          </p>
        </div>
      </div>

      {/* Risk Reasons */}
      {result.risk_reasons?.length > 0 && (
        <div className="p-5 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-300 space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" />
            Identified Telephony Risk Indicators
          </h4>
          <ul className="space-y-1 text-xs">
            {result.risk_reasons.map((reason, idx) => (
              <li key={idx} className="flex items-start space-x-2">
                <span className="text-rose-400 font-bold">•</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default PhoneResultCard;
