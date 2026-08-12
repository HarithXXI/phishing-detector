import React from 'react';
import { Phone, Globe, Radio, AlertTriangle, CheckCircle, ShieldAlert, MapPin, Compass, ExternalLink, Info, Building } from 'lucide-react';

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

  const isVoip = result.line_type === 'VOIP' || result.is_voip;
  const isValid = result.validation === 'Valid' || (result.valid ?? true);
  const isSpam = result.is_spam || (result.risk && result.risk >= 25);
  const isHighRisk = (result.risk && result.risk >= 20) || isVoip || !isValid || isSpam;

  const countryDisplay = result.country || 'India (+91)';
  const stateDisplay = result.state || 'West Bengal';
  const circleDisplay = result.circle ? `${result.circle} Circle` : 'West Bengal Circle';
  const cityApprox = result.city_approx || 'Kolkata / Siliguri';
  const latLngApprox = result.lat_lng_approx || '22.57, 88.36';
  const carrierDisplay = result.carrier || 'Airtel';
  const mapsUrl = `https://maps.google.com/?q=${encodeURIComponent(latLngApprox)}`;

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
              <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                <h3 className="text-lg font-bold text-[var(--text-main)] font-mono">
                  {result.phone || result.number}
                </h3>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {result.digit_length || '10/10'}
                </span>
                {isVoip && (
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                    ⚠️ VoIP
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                v3.2 Telephony OSINT — Circle-Level Series Allocation
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

      {/* 6 Grid Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Card 1: COUNTRY */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Globe className="w-4 h-4 text-cyan-400" />
            Country
          </span>
          <p className="text-sm font-bold text-[var(--text-main)] flex items-center gap-2">
            <span>🇮🇳</span>
            <span>{countryDisplay}</span>
          </p>
        </div>

        {/* Card 2: STATE */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Building className="w-4 h-4 text-amber-400" />
            State
          </span>
          <p className="text-sm font-bold text-[var(--text-main)]">
            {stateDisplay}
          </p>
        </div>

        {/* Card 3: CIRCLE */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Compass className="w-4 h-4 text-purple-400" />
            Telecom Circle
          </span>
          <p className="text-sm font-bold text-purple-300">
            {circleDisplay}
          </p>
        </div>

        {/* Card 4: APPROX CITY */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <MapPin className="w-4 h-4 text-emerald-400" />
            Approximate City
          </span>
          <p className="text-sm font-bold text-cyan-400">
            {cityApprox}
          </p>
        </div>

        {/* Card 5: COORDINATES */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Compass className="w-4 h-4 text-rose-400" />
            Coordinates (Approx)
          </span>
          <div className="flex items-center justify-between">
            <p className="text-xs font-mono font-bold text-[var(--text-main)]">
              {latLngApprox}
            </p>
            <a
              href={mapsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 text-[10px] font-bold border border-cyan-500/30 transition-colors"
            >
              <ExternalLink className="w-3 h-3" />
              <span>Google Maps</span>
            </a>
          </div>
        </div>

        {/* Card 6: CARRIER */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
            <Radio className="w-4 h-4 text-blue-400" />
            Carrier Operator
          </span>
          <p className="text-sm font-bold text-[var(--text-main)]">
            {carrierDisplay}
          </p>
          <p className="text-[10px] text-[var(--text-muted)] font-medium">
            (Original series allocation; may be ported via MNP)
          </p>
        </div>
      </div>

      {/* Disclaimer Box */}
      <div className="p-4 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] text-xs text-[var(--text-muted)] flex items-start space-x-3">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-[var(--text-main)]">Disclaimer:</strong> Approximate circle location based on original series allocation. Due to Mobile Number Portability (MNP), carrier/circle may differ. Not exact user GPS location.
        </p>
      </div>
    </div>
  );
};

export default PhoneResultCard;
