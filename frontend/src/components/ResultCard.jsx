import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Globe,
  Server,
  Activity,
  Database,
  AlertCircle,
  MapPin,
  Cpu,
  Lock,
  ExternalLink
} from 'lucide-react';
import DnsCard from './DnsCard';

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
    attack_vector = '',
    attack_type = 'unknown',
    breakdown = {},
    dns = {},
    ip_details = {},
    whois = {},
    virustotal = {},
    abuseipdb = {},
    ai_result = {},
    final_url = '',
    extracted = {},
    risk_factors = [],
    cached = false
  } = result;

  const displayScore = risk_score ?? score;
  const level = (risk_level || 'LOW').toUpperCase();
  const styles = LEVEL_STYLE[level] || LEVEL_STYLE.LOW;

  const displayVector = attack_vector ||
    attack_type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

  const isIpApplicable = ip_details?.is_applicable !== false && ip_details?.ip && ip_details?.ip !== '';

  const LAYER_CARDS = [
    {
      key: 'ai',
      label: 'AI Brain Intent',
      icon: <Cpu className="w-4 h-4 text-purple-400" />,
      max: 40,
      desc: ai_result?.reasons?.[0] || 'Groq/Gemini LLM multimodal intent verification.',
    },
    {
      key: 'dns',
      label: 'DNS Security',
      icon: <Activity className="w-4 h-4 text-cyan-400" />,
      max: 40,
      desc: dns?.status || 'A, MX, SPF & DMARC infrastructure verification.',
    },
    {
      key: 'ip',
      label: 'IP / Hosting',
      icon: <MapPin className="w-4 h-4 text-emerald-400" />,
      max: 25,
      desc: isIpApplicable ? `Location: ${ip_details.location || 'Global Node'}` : 'No IP to check for text-only input.',
    },
    {
      key: 'whois',
      label: 'WHOIS Domain Age',
      icon: <Database className="w-4 h-4 text-amber-500" />,
      max: 20,
      desc: whois?.age_days != null ? `Domain age: ${whois.age_days} days` : whois?.reason || 'Registry lookup evaluated.',
    },
    {
      key: 'vt',
      label: 'VirusTotal Threat Intel',
      icon: <Server className="w-4 h-4 text-emerald-500" />,
      max: 40,
      desc: `Malicious: ${virustotal?.malicious || 0} | Suspicious: ${virustotal?.suspicious || 0}`,
    },
    {
      key: 'abuse',
      label: 'AbuseIPDB Reputation',
      icon: <AlertCircle className="w-4 h-4 text-rose-500" />,
      max: 35,
      desc: `Abuse Confidence: ${abuseipdb?.abuseConfidenceScore || 0}%`,
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
                v3.2 PhishGuard Generic AI Threat Engine
              </p>
              {final_url && final_url !== result?.extracted?.primary_url && (
                <div className="mt-1 flex items-center gap-1.5 text-xs text-amber-400 font-mono">
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Expanded URL: {final_url}</span>
                </div>
              )}
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
        <DnsCard dns={dns} />

        {/* IP Detail Finder Card */}
        <div className="p-5 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <MapPin className="w-4 h-4 text-emerald-400" />
              IP Detail & Hosting Finder
            </span>
            {isIpApplicable && (
              <span className="text-xs font-mono font-bold text-cyan-400">
                {ip_details.ip}
              </span>
            )}
          </div>

          {isIpApplicable ? (
            <div className="space-y-2 text-xs text-[var(--text-muted)]">
              <div className="flex justify-between border-b border-[var(--border)] pb-1.5">
                <span>Location:</span>
                <span className="font-semibold text-[var(--text-main)]">
                  {ip_details.location || 'Global Node'}
                </span>
              </div>
              <div className="flex justify-between border-b border-[var(--border)] pb-1.5">
                <span>ISP / Network:</span>
                <span className="font-semibold text-[var(--text-main)] truncate max-w-[200px]">
                  {ip_details.isp || 'Cloud Network Host'}
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
                    Proxy / VPN Node
                  </span>
                )}
              </div>
            </div>
          ) : (
            <p className="text-xs text-[var(--text-muted)] pt-2">
              No IP address to check — text analysis mode active.
            </p>
          )}
        </div>
      </div>

      {/* Grid Row 2: 6 Detection Layer Score Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {LAYER_CARDS.map(({ key, label, icon, max, desc }) => {
          const pts = breakdown[key] ?? 0;
          const pct = Math.round((pts / max) * 100);
          const barColor =
            pct >= 70 ? 'bg-rose-500' :
            pct >= 40 ? 'bg-amber-500' :
            'bg-emerald-500';
          return (
            <div key={key} className="p-4 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
                  {icon}
                  {label}
                </span>
                <span className="text-sm font-bold text-[var(--text-main)]">
                  {pts} <span className="text-[10px] text-[var(--text-muted)] font-normal">/ {max} pts</span>
                </span>
              </div>
              <div className="w-full h-1.5 rounded-full bg-[var(--bg-input)] overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${barColor}`}
                  style={{ width: `${Math.min(100, pct)}%` }}
                />
              </div>
              <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{desc}</p>
            </div>
          );
        })}
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
