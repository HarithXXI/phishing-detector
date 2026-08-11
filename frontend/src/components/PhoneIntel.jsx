import React, { useState } from 'react';
import { Phone, Search, AlertTriangle, CheckCircle, ShieldAlert, Globe, Radio, Clock } from 'lucide-react';

export default function PhoneIntel() {
  const [phone, setPhone] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const lookup = async () => {
    if (!phone.trim()) return;
    setLoading(true);
    try {
      const res = await fetch('/api/phone-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone })
      });
      const data = await res.json();
      setResult(data);
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      lookup();
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto space-y-6">
      <div className="p-6 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] transition-all">
        <div className="flex items-center space-x-3 mb-2">
          <div className="p-2.5 rounded-xl bg-cyan-500/20 text-cyan-400">
            <Phone className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-[var(--text-main)]">📱 Phone Number Intel OSINT</h2>
            <p className="text-xs text-[var(--text-muted)]">
              Caller-ID + numint OSINT inspection: Carrier lookup, country geolocation, line type, & VoIP fraud detection.
            </p>
          </div>
        </div>

        <div className="flex gap-2 my-6">
          <input
            type="text"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="+91 9876543210 or +1 415 555 2671"
            className="flex-1 bg-[var(--bg-input)] border border-[var(--border)] rounded-xl px-4 py-3 text-sm text-[var(--text-main)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500 transition-colors"
          />
          <button
            onClick={lookup}
            disabled={loading}
            className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-6 py-3 rounded-xl transition-all disabled:opacity-50 flex items-center space-x-2 shadow-lg shadow-cyan-600/20"
          >
            <Search className="w-4 h-4" />
            <span>{loading ? 'Scanning...' : 'Lookup'}</span>
          </button>
        </div>

        {result && !result.error && (
          <div className="space-y-4 animate-in fade-in slide-in-from-bottom-3 duration-300">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="bg-[var(--bg-input)] border border-[var(--border)] rounded-xl p-4 space-y-1">
                <p className="text-[var(--text-muted)] font-medium">International Number</p>
                <p className="text-[var(--text-main)] font-mono font-bold text-sm">{result.international || result.number || 'N/A'}</p>
              </div>

              <div className="bg-[var(--bg-input)] border border-[var(--border)] rounded-xl p-4 space-y-1">
                <p className="text-[var(--text-muted)] font-medium">Country & Code</p>
                <p className="text-[var(--text-main)] font-bold text-sm flex items-center gap-1.5">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  {result.country || 'Unknown'} (+{result.country_code || 'N/A'})
                </p>
              </div>

              <div className="bg-[var(--bg-input)] border border-[var(--border)] rounded-xl p-4 space-y-1">
                <p className="text-[var(--text-muted)] font-medium">Carrier Operator</p>
                <p className="text-[var(--text-main)] font-bold text-sm flex items-center gap-1.5">
                  <Radio className="w-4 h-4 text-blue-400" />
                  {result.carrier || 'Unknown'}
                </p>
              </div>

              <div className="bg-[var(--bg-input)] border border-[var(--border)] rounded-xl p-4 space-y-1">
                <p className="text-[var(--text-muted)] font-medium">Line Type</p>
                <p className={`font-bold text-sm flex items-center gap-1.5 ${result.is_voip ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.line_type || 'UNKNOWN'}
                  {result.is_voip && (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      ⚠️ VoIP
                    </span>
                  )}
                </p>
              </div>

              <div className="bg-[var(--bg-input)] border border-[var(--border)] rounded-xl p-4 space-y-1">
                <p className="text-[var(--text-muted)] font-medium">Validation Status</p>
                <p className={`font-bold text-sm flex items-center gap-1.5 ${result.is_valid ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {result.is_valid ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                  {result.is_valid ? 'Valid Number' : 'Invalid Number'} / {result.is_possible ? 'Possible' : 'Impossible'}
                </p>
              </div>

              <div className="bg-[var(--bg-input)] border border-[var(--border)] rounded-xl p-4 space-y-1">
                <p className="text-[var(--text-muted)] font-medium">Timezones</p>
                <p className="text-[var(--text-main)] font-bold text-sm flex items-center gap-1.5">
                  <Clock className="w-4 h-4 text-amber-400" />
                  {result.timezones?.length ? result.timezones.join(', ') : 'Unknown'}
                </p>
              </div>

              {result.risk > 0 && (
                <div className="md:col-span-2 bg-rose-500/10 border border-rose-500/30 rounded-xl p-4 space-y-1 text-rose-300">
                  <div className="flex items-center space-x-2 font-bold text-sm text-rose-400">
                    <ShieldAlert className="w-5 h-5" />
                    <span>Risk Score: {result.risk}/100</span>
                  </div>
                  <p className="text-xs text-[var(--text-muted)]">
                    {result.risk_reasons?.join(', ') || 'VoIP or high-risk line type detected.'}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {result?.error && (
          <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-4 text-rose-400 text-xs font-semibold">
            {result.error}
          </div>
        )}
      </div>
    </div>
  );
}
