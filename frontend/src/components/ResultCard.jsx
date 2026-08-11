import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Globe,
  Server,
  Activity,
  Database,
  AlertCircle,
  CheckCircle2,
  XCircle,
  MapPin,
  Radio,
  HardDrive
} from 'lucide-react';

export const ResultCard = ({ result }) => {
  if (!result) return null;

  const {
    score = 0,
    risk_level = 'LOW',
    attack_type = 'unknown',
    breakdown = {},
    whois = {},
    ml_model = {},
    virustotal = {},
    abuseipdb = {},
    ai_result = {},
    dns = {},
    ip_details = {},
    osint = {},
    risk_factors = [],
    cached = false
  } = result;

  const isHighRisk = score >= 65 || risk_level === 'HIGH' || risk_level === 'CRITICAL';
  const isMediumRisk = score >= 30 || risk_level === 'MEDIUM';

  const formatAttackType = (type) => {
    return type
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  const dnsChecks = dns?.checks || {};
  const hasNoMx = dnsChecks.MX === false || (dns?.MX && dns.MX.length === 0);

  return (
    <div className="w-full space-y-6">
      {/* Top Banner Card */}
      <div
        className={`p-6 rounded-2xl border transition-all duration-300 ${
          isHighRisk
            ? 'border-rose-500/40 bg-rose-500/10 text-rose-300 shadow-xl'
            : isMediumRisk
            ? 'border-amber-500/40 bg-amber-500/10 text-amber-300 shadow-xl'
            : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300 shadow-xl'
        }`}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${
                isHighRisk
                  ? 'bg-rose-500/20 text-rose-400'
                  : isMediumRisk
                  ? 'bg-amber-500/20 text-amber-400'
                  : 'bg-emerald-500/20 text-emerald-400'
              }`}
            >
              {isHighRisk ? <ShieldAlert className="w-7 h-7" /> : <ShieldCheck className="w-7 h-7" />}
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-lg font-bold text-[var(--text-main)]">
                  Attack Vector: <span className="text-cyan-500 font-extrabold">{formatAttackType(attack_type)}</span>
                </h3>
                {cached && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-500 border border-cyan-500/20">
                    Cached 24h
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                v3.1 OSINT & Multi-Layer Threat Verification Analysis
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span
              className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                isHighRisk
                  ? 'bg-rose-500/20 text-rose-500 border-rose-500/40'
                  : isMediumRisk
                  ? 'bg-amber-500/20 text-amber-500 border-amber-500/40'
                  : 'bg-emerald-500/20 text-emerald-500 border-emerald-500/40'
              }`}
            >
              {risk_level} RISK ({score}%)
            </span>
          </div>
        </div>
      </div>

      {/* OSINT & Detection Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* DNS Checker Card */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3 col-span-1 md:col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Radio className="w-4 h-4 text-cyan-400" />
              DNS & Email Records
            </span>
            {hasNoMx && (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                Fake domain - No mail server
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="flex items-center justify-between p-2 rounded bg-[var(--bg-input)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)]">A Record:</span>
              {dnsChecks.A ? (
                <span className="flex items-center text-emerald-400 font-bold gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Valid
                </span>
              ) : (
                <span className="flex items-center text-rose-400 font-bold gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Missing
                </span>
              )}
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-[var(--bg-input)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)]">MX Server:</span>
              {dnsChecks.MX ? (
                <span className="flex items-center text-emerald-400 font-bold gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Active
                </span>
              ) : (
                <span className="flex items-center text-rose-400 font-bold gap-1">
                  <XCircle className="w-3.5 h-3.5" /> None
                </span>
              )}
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-[var(--bg-input)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)]">SPF Record:</span>
              {dnsChecks.SPF ? (
                <span className="flex items-center text-emerald-400 font-bold gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Pass
                </span>
              ) : (
                <span className="flex items-center text-rose-400 font-bold gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Missing
                </span>
              )}
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-[var(--bg-input)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)]">DMARC:</span>
              {dnsChecks.DMARC ? (
                <span className="flex items-center text-emerald-400 font-bold gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Protected
                </span>
              ) : (
                <span className="flex items-center text-rose-400 font-bold gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Missing
                </span>
              )}
            </div>
          </div>
        </div>

        {/* IP Detail Finder Card */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3 col-span-1 md:col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <MapPin className="w-4 h-4 text-emerald-400" />
              IP Detail Finder
            </span>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {ip_details?.ip || 'N/A'}
            </span>
          </div>

          <div className="space-y-1.5 text-xs text-[var(--text-muted)]">
            <div className="flex justify-between border-b border-[var(--border)] pb-1">
              <span>Location:</span>
              <span className="font-semibold text-[var(--text-main)]">
                {[ip_details?.geo?.city, ip_details?.geo?.country].filter(Boolean).join(', ') || 'Unknown'}
              </span>
            </div>
            <div className="flex justify-between border-b border-[var(--border)] pb-1">
              <span>ISP / Network:</span>
              <span className="font-semibold text-[var(--text-main)] truncate max-w-[180px]">
                {ip_details?.asn?.isp || ip_details?.asn?.org || 'Unknown'}
              </span>
            </div>
            <div className="flex items-center gap-2 pt-1">
              {ip_details?.is_proxy && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  Proxy / VPN Detected
                </span>
              )}
              {ip_details?.is_hosting && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  Hosting Server IP
                </span>
              )}
              {!ip_details?.is_proxy && !ip_details?.is_hosting && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Direct Resident IP
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Layer 1: Rule Engine */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-cyan-500" />
              Rule Signatures
            </span>
            <span className="text-sm font-bold text-[var(--text-main)]">{breakdown.rule_engine || 0} pts</span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Regex heuristics & malicious regex patterns match score.
          </p>
        </div>

        {/* Layer 2: URL Heuristics */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-blue-500" />
              URL Structure
            </span>
            <span className="text-sm font-bold text-[var(--text-main)]">{breakdown.url_heuristic || 0} pts</span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Typosquatting, Shannon entropy & path complexity checks.
          </p>
        </div>

        {/* Layer 3: WHOIS Domain Age */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Database className="w-4 h-4 text-amber-500" />
              WHOIS Domain Age
            </span>
            <span className="text-sm font-bold text-[var(--text-main)]">{breakdown.whois_age || 0} pts</span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            {whois?.age_days !== undefined && whois?.age_days !== null
              ? `Domain age: ${whois.age_days} days (Created: ${whois.creation_date || 'N/A'})`
              : whois?.reason || 'WHOIS registry lookup evaluated'}
          </p>
          {breakdown.young_domain_boost > 0 && (
            <span className="inline-block text-[10px] font-bold text-amber-600 dark:text-amber-300 bg-amber-500/20 px-2 py-0.5 rounded border border-amber-500/30">
              +{breakdown.young_domain_boost} {breakdown.young_domain_boost === 20 ? 'Young Domain Boost (<30d)' : 'Restricted WHOIS Boost'}
            </span>
          )}
        </div>

        {/* Layer 4: VirusTotal Threat Intel */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Server className="w-4 h-4 text-emerald-500" />
              VirusTotal (70 Vendors)
            </span>
            <span className="text-sm font-bold text-[var(--text-main)]">{breakdown.virustotal || 0} pts</span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Malicious: {virustotal?.malicious || 0} | Suspicious: {virustotal?.suspicious || 0}
          </p>
        </div>

        {/* Layer 5: AbuseIPDB Reputation */}
        <div className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <AlertCircle className="w-4 h-4 text-rose-500" />
              AbuseIPDB Reputation
            </span>
            <span className="text-sm font-bold text-[var(--text-main)]">{breakdown.abuseipdb || 0} pts</span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Abuse Confidence Score: {abuseipdb?.abuseConfidenceScore || 0}%
          </p>
        </div>
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
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ResultCard;
