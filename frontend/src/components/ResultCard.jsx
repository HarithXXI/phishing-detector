import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Globe,
  Server,
  Activity,
  Database,
  AlertCircle,
  CheckCircle2,
  XCircle,
  MapPin,
  Radio,
  Cpu,
  Zap,
  Search,
  Lock
} from 'lucide-react';

// Tooltip wrapper — shows pt calculation on hover
const ScoreTooltip = ({ label, pts, max, how, children }) => {
  const [show, setShow] = useState(false);
  return (
    <div
      className="relative"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-52 p-2.5 rounded-xl
          bg-slate-900/95 border border-cyan-500/30 shadow-2xl text-[10px] text-slate-300 leading-relaxed pointer-events-none">
          <p className="font-bold text-cyan-400 mb-1">{label}</p>
          <p>{how}</p>
          <p className="mt-1 font-semibold text-white">Score: <span className="text-cyan-300">{pts} / {max} pts</span></p>
        </div>
      )}
    </div>
  );
};

const LEVEL_STYLE = {
  CRITICAL: {
    banner: 'border-red-600/50 bg-red-600/10 text-red-300 shadow-xl shadow-red-900/20',
    icon: 'bg-red-600/20 text-red-400',
    badge: 'bg-red-600/20 text-red-400 border-red-600/40',
  },
  HIGH: {
    banner: 'border-rose-500/40 bg-rose-500/10 text-rose-300 shadow-xl',
    icon: 'bg-rose-500/20 text-rose-400',
    badge: 'bg-rose-500/20 text-rose-500 border-rose-500/40',
  },
  MEDIUM: {
    banner: 'border-amber-500/40 bg-amber-500/10 text-amber-300 shadow-xl',
    icon: 'bg-amber-500/20 text-amber-400',
    badge: 'bg-amber-500/20 text-amber-500 border-amber-500/40',
  },
  LOW: {
    banner: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300 shadow-xl',
    icon: 'bg-emerald-500/20 text-emerald-400',
    badge: 'bg-emerald-500/20 text-emerald-500 border-emerald-500/40',
  },
};

export const ResultCard = ({ result }) => {
  if (!result) return null;

  const {
    score = 0,
    risk_score,
    risk_level = 'LOW',
    attack_type = 'unknown',
    attack_vector = '',
    dns_status = '',
    breakdown = {},
    whois = {},
    virustotal = {},
    abuseipdb = {},
    ai_result = {},
    dns = {},
    ip_details = {},
    risk_factors = [],
    cached = false
  } = result;

  const displayScore = risk_score ?? score;
  const level = risk_level?.toUpperCase() || 'LOW';
  const styles = LEVEL_STYLE[level] || LEVEL_STYLE.LOW;

  // Attack vector — prefer new field, fall back to attack_type
  const displayVector = attack_vector ||
    attack_type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

  // DNS status badge
  const dnsChecks = dns?.checks || {};
  const isAMissing = dnsChecks.A === false;
  const isMxMissing = dnsChecks.MX === false || (!dns?.MX || (Array.isArray(dns.MX) && dns.MX.length === 0));

  // dns_status from backend scoring overrides legacy logic
  const dnsBadgeLabel = dns_status && dns_status !== 'Valid Domain'
    ? dns_status
    : isAMissing ? 'Domain does not exist - Fake'
    : isMxMissing ? 'No MX Mail Server'
    : 'Active Domain';

  const dnsBadgeStyle = (dns_status === 'Domain does not exist - Fake' || isAMissing)
    ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
    : (dns_status === 'No mail server - suspicious' || (!isAMissing && isMxMissing))
    ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    : (dns_status === 'No MX but SPF present - OK' || dns_status === 'Missing DMARC')
    ? 'bg-amber-400/20 text-amber-300 border-amber-400/30'
    : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';

  const LAYER_INFO = [
    {
      key: 'rule',
      label: 'Rule Signatures',
      icon: <Activity className="w-4 h-4 text-cyan-500" />,
      max: 35,
      how: 'Regex & keyword match. Critical keywords (PayPal secure, account blocked) boosted up to 25 pts each.',
      desc: 'Regex heuristics & phishing keyword match score.',
    },
    {
      key: 'url',
      label: 'URL Structure',
      icon: <Globe className="w-4 h-4 text-blue-500" />,
      max: 25,
      how: 'Typosquatting, suspicious TLD, Shannon entropy, IP-in-URL, path complexity.',
      desc: 'Typosquatting, entropy & path complexity checks.',
    },
    {
      key: 'whois',
      label: 'WHOIS Domain Age',
      icon: <Database className="w-4 h-4 text-amber-500" />,
      max: 20,
      how: '<30d = 20pts, 30-90d = 12pts, 90-365d = 5pts, older = 0pts.',
      desc: whois?.age_days != null ? `Domain age: ${whois.age_days} days` : whois?.reason || 'Registry lookup evaluated.',
    },
    {
      key: 'vt',
      label: 'VirusTotal Threat Intel',
      icon: <Server className="w-4 h-4 text-emerald-500" />,
      max: 40,
      how: 'Each malicious engine flag = 8 pts. Capped at 40 pts (5 flags = HIGH).',
      desc: `Malicious: ${virustotal?.malicious || 0} | Suspicious: ${virustotal?.suspicious || 0}`,
    },
    {
      key: 'abuse',
      label: 'AbuseIPDB Reputation',
      icon: <AlertCircle className="w-4 h-4 text-rose-500" />,
      max: 35,
      how: 'AbuseIPDB confidence score × 0.35. Capped at 35 pts.',
      desc: `Abuse Confidence Score: ${abuseipdb?.abuseConfidenceScore || 0}%`,
    },
    {
      key: 'ai',
      label: 'AI Safety Reasoning',
      icon: <Cpu className="w-4 h-4 text-purple-400" />,
      max: 30,
      how: 'Gemini/Groq LLM classifies intent. is_phishing = 30 pts, else 0 pts.',
      desc: 'Gemini AI LLM multimodal intent verification.',
    },
    {
      key: 'dns',
      label: 'DNS Security',
      icon: <Radio className="w-4 h-4 text-cyan-400" />,
      max: 40,
      how: 'No A record = 40pts (fake). No MX+SPF = 15pts. No MX only = 3pts. No DMARC = 5pts.',
      desc: dns_status || 'MX, SPF & DMARC validation.',
    },
    {
      key: 'ip',
      label: 'IP / Hosting',
      icon: <MapPin className="w-4 h-4 text-emerald-400" />,
      max: 40,
      how: 'Proxy/VPN = 25pts. Hosting IP = 5pts. Abuse confidence >50% adds 15pts.',
      desc: ip_details?.ip ? `IP: ${ip_details.ip}` : 'IP & hosting reputation check.',
    },
    {
      key: 'harvester',
      label: 'Subdomain Footprint',
      icon: <Search className="w-4 h-4 text-indigo-400" />,
      max: 12,
      how: '0 subdomains = 12pts (no footprint). <3 subdomains = 5pts.',
      desc: 'crt.sh SSL certificate subdomain enumeration.',
    },
    {
      key: 'wfuzz',
      label: 'Phishing Kit Paths',
      icon: <Zap className="w-4 h-4 text-orange-400" />,
      max: 25,
      how: 'Each exposed phishing kit path = 8 pts. Capped at 25 pts.',
      desc: 'Wfuzz scan for common phishing kit drop paths.',
    },
  ];

  return (
    <div className="w-full space-y-6">
      {/* Top Banner Card */}
      <div className={`p-6 rounded-2xl border transition-all duration-300 ${styles.banner}`}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${styles.icon}`}>
              {level === 'LOW' ? <ShieldCheck className="w-7 h-7" /> : <ShieldAlert className="w-7 h-7" />}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-lg font-bold text-[var(--text-main)]">
                  Attack Vector: <span className="text-cyan-500 font-extrabold">{displayVector}</span>
                </h3>
                {cached && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-500 border border-cyan-500/20">
                    Cached 24h
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                v3.2 PhishGuard Multimodal OSINT & Threat Analysis Engine
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${styles.badge}`}>
              {level} RISK ({displayScore}%)
            </span>
          </div>
        </div>
      </div>

      {/* Grid Row 1: OSINT Infrastructure Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* DNS Checker Card */}
        <div className="p-5 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Radio className="w-4 h-4 text-cyan-400" />
              DNS Security & Mail Records
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${dnsBadgeStyle}`}>
              {dnsBadgeLabel}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            {[
              { key: 'A', label: 'A Record', ok: 'Valid', bad: 'Missing', okColor: 'text-emerald-400', badColor: 'text-rose-400' },
              { key: 'MX', label: 'MX Server', ok: 'Active', bad: 'None', okColor: 'text-emerald-400', badColor: 'text-amber-400' },
              { key: 'SPF', label: 'SPF Record', ok: 'Pass', bad: 'Missing', okColor: 'text-emerald-400', badColor: 'text-amber-400' },
              { key: 'DMARC', label: 'DMARC', ok: 'Protected', bad: 'Missing', okColor: 'text-emerald-400', badColor: 'text-amber-400' },
            ].map(({ key, label, ok, bad, okColor, badColor }) => {
              const val = dnsChecks[key];
              const isOk = val !== false && val !== null && val !== undefined && val !== '';
              return (
                <div key={key} className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)]">
                  <span className="text-[var(--text-muted)]">{label}:</span>
                  {isOk ? (
                    <span className={`flex items-center font-bold gap-1 ${okColor}`}>
                      <CheckCircle2 className="w-3.5 h-3.5" /> {ok}
                    </span>
                  ) : (
                    <span className={`flex items-center font-bold gap-1 ${key === 'A' ? 'text-rose-400' : badColor}`}>
                      {key === 'A' ? <XCircle className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />} {bad}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* IP Detail Finder Card */}
        <div className="p-5 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <MapPin className="w-4 h-4 text-emerald-400" />
              IP Detail & Hosting Finder
            </span>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {ip_details?.ip || 'N/A'}
            </span>
          </div>

          <div className="space-y-2 text-xs text-[var(--text-muted)]">
            <div className="flex justify-between border-b border-[var(--border)] pb-1.5">
              <span>Location:</span>
              <span className="font-semibold text-[var(--text-main)]">
                {[ip_details?.geo?.city, ip_details?.geo?.country].filter(Boolean).join(', ') || 'Global IP'}
              </span>
            </div>
            <div className="flex justify-between border-b border-[var(--border)] pb-1.5">
              <span>ISP / Network:</span>
              <span className="font-semibold text-[var(--text-main)] truncate max-w-[200px]">
                {ip_details?.asn?.isp || ip_details?.asn?.org || 'Cloud Provider'}
              </span>
            </div>
            <div className="flex items-center gap-2 pt-1">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                ip_details?.is_hosting
                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
              }`}>
                {ip_details?.is_hosting ? 'Hosting IP' : 'Residential IP'}
              </span>

              {ip_details?.is_proxy && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  Proxy / VPN
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Grid Row 2: 10 Detection Layer Score Cards with Tooltips */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {LAYER_INFO.map(({ key, label, icon, max, how, desc }) => {
          const pts = breakdown[key] ?? 0;
          const pct = Math.round((pts / max) * 100);
          const barColor =
            pct >= 70 ? 'bg-rose-500' :
            pct >= 40 ? 'bg-amber-500' :
            'bg-emerald-500';
          return (
            <ScoreTooltip key={key} label={label} pts={pts} max={max} how={how}>
              <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2 cursor-help hover:border-cyan-500/40 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
                    {icon}
                    {label}
                  </span>
                  <span className="text-sm font-bold text-[var(--text-main)]">{pts} <span className="text-[10px] text-[var(--text-muted)] font-normal">/ {max}</span></span>
                </div>
                {/* Mini progress bar */}
                <div className="w-full h-1.5 rounded-full bg-[var(--bg-input)] overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${barColor}`}
                    style={{ width: `${Math.min(100, pct)}%` }}
                  />
                </div>
                <p className="text-[11px] text-[var(--text-muted)]">{desc}</p>
              </div>
            </ScoreTooltip>
          );
        })}
      </div>

      {/* Score sum confirmation */}
      <div className="flex items-center justify-end gap-2 text-[11px] text-[var(--text-muted)]">
        <Lock className="w-3 h-3 text-cyan-500/60" />
        <span>
          Breakdown sum:{' '}
          <span className="font-bold text-cyan-400">
            {LAYER_INFO.reduce((acc, { key }) => acc + (breakdown[key] ?? 0), 0)} pts
          </span>{' '}
          → Gauge: <span className="font-bold text-cyan-400">{displayScore}%</span>
        </span>
      </div>

      {/* AI Reasons & Safety Flags */}
      {(risk_factors.length > 0 || ai_result?.reasons?.length > 0) && (
        <div className="p-5 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-main)] flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-cyan-500" />
            Identified Threat Indicators & Explanations
          </h4>

          <ul className="space-y-2">
            {[...(risk_factors || []), ...(ai_result?.reasons || [])].slice(0, 6).map((reason, idx) => (
              <li key={idx} className="text-xs text-[var(--text-muted)] flex items-start space-x-2">
                <span className="text-cyan-500 font-bold">•</span>
                <span>{typeof reason === 'object' ? (reason.rule || JSON.stringify(reason)) : reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ResultCard;
