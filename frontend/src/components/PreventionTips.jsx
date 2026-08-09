import React from 'react';
import {
  Link2,
  Lock,
  Mail,
  Image,
  AlertOctagon,
  ShieldCheck,
  Smartphone,
  Eye,
  PhoneCall,
  Sparkles,
  CheckSquare,
  RefreshCw,
  ExternalLink
} from 'lucide-react';

const ALL_TIPS = [
  {
    id: 1,
    tag: ['high', 'email', 'all'],
    icon: Link2,
    iconColor: 'text-cyan-500',
    iconBg: 'bg-cyan-500/10 border-cyan-500/20',
    badgeText: 'Check URL',
    badgeClass: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
    title: 'Check URL Carefully',
    desc: 'Hover over links before clicking. Look for suspicious hyphens, @ symbols, or typo-squatted domains like paypaI.com instead of paypal.com.'
  },
  {
    id: 2,
    tag: ['high', 'medium', 'website', 'all'],
    icon: Lock,
    iconColor: 'text-amber-500',
    iconBg: 'bg-amber-500/10 border-amber-500/20',
    badgeText: 'Domain Age <30d',
    badgeClass: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
    title: 'Domain Age <30 Days = 90% Scam',
    desc: 'New domains registered less than 30 days ago carry a high scam probability. Always verify WHOIS domain creation dates.'
  },
  {
    id: 3,
    tag: ['high', 'phone', 'sms', 'all'],
    icon: Mail,
    iconColor: 'text-purple-500',
    iconBg: 'bg-purple-500/10 border-purple-500/20',
    badgeText: 'For SMS Scams',
    badgeClass: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
    title: 'Banks Never Ask OTP via Link',
    desc: 'SBI, HDFC & PayPal never demand confidential OTPs, PINs, or passwords via SMS or email links.'
  },
  {
    id: 4,
    tag: ['high', 'all'],
    icon: Image,
    iconColor: 'text-rose-500',
    iconBg: 'bg-rose-500/10 border-rose-500/20',
    badgeText: 'For High Risk',
    badgeClass: 'bg-rose-500/10 text-rose-500 border-rose-500/20',
    title: 'Fake Payment Screenshots',
    desc: 'Scammers send fake GPay/PhonePe success screens. Always verify received funds directly inside your official app.'
  },
  {
    id: 5,
    tag: ['high', 'all'],
    icon: AlertOctagon,
    iconColor: 'text-rose-500',
    iconBg: 'bg-rose-500/10 border-rose-500/20',
    badgeText: 'For High Risk',
    badgeClass: 'bg-rose-500/10 text-rose-500 border-rose-500/20',
    title: 'Urgency & Threat Trap',
    desc: 'Demands like "Account blocked in 2 hours" are classic phishing psychological pressure tactics to force quick action.'
  },
  {
    id: 6,
    tag: ['medium', 'high', 'all'],
    icon: ShieldCheck,
    iconColor: 'text-blue-500',
    iconBg: 'bg-blue-500/10 border-blue-500/20',
    badgeText: 'Account Safety',
    badgeClass: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    title: 'Enable 2FA with Authenticator',
    desc: 'Protect accounts using Google/Microsoft Authenticator apps instead of SMS OTPs which can be SIM-swapped.'
  },
  {
    id: 7,
    tag: ['low', 'medium', 'all'],
    icon: Smartphone,
    iconColor: 'text-emerald-500',
    iconBg: 'bg-emerald-500/10 border-emerald-500/20',
    badgeText: 'Good Habit',
    badgeClass: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
    title: 'Use Official Apps Only',
    desc: 'Don\'t click SMS links. Open your official SBI, HDFC, or PayPal app directly from your phone launcher.'
  },
  {
    id: 8,
    tag: ['high', 'email', 'website'],
    icon: Eye,
    iconColor: 'text-cyan-500',
    iconBg: 'bg-cyan-500/10 border-cyan-500/20',
    badgeText: 'Link Preview',
    badgeClass: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
    title: 'Hover Before You Click',
    desc: 'On desktop hover over links to preview destination URL. On mobile long-press link to reveal true domain.'
  },
  {
    id: 9,
    tag: ['high', 'all'],
    icon: PhoneCall,
    iconColor: 'text-amber-500',
    iconBg: 'bg-amber-500/10 border-amber-500/20',
    badgeText: 'Golden Hour',
    badgeClass: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
    title: 'Report in 1 Hour = 80% Recovery',
    desc: 'If scammed, call 1930 or report on cybercrime.gov.in within the 1-hour Golden Hour to freeze stolen funds.'
  },
  {
    id: 10,
    tag: ['all'],
    icon: Sparkles,
    iconColor: 'text-indigo-500',
    iconBg: 'bg-indigo-500/10 border-indigo-500/20',
    badgeText: 'Best Practice',
    badgeClass: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
    title: 'Test Every Suspicious Message',
    desc: 'Paste suspicious SMS, emails, or links into PhishGuard before interacting.'
  },
  {
    id: 11,
    tag: ['email'],
    icon: CheckSquare,
    iconColor: 'text-blue-500',
    iconBg: 'bg-blue-500/10 border-blue-500/20',
    badgeText: 'For Email Phishing',
    badgeClass: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    title: 'Check Email Header SPF/DKIM',
    desc: 'Fake emails fail SPF/DKIM verification. Check sender domain carefully (e.g., support@paypal.scam.com).'
  },
  {
    id: 12,
    tag: ['low', 'all'],
    icon: RefreshCw,
    iconColor: 'text-teal-500',
    iconBg: 'bg-teal-500/10 border-teal-500/20',
    badgeText: 'System Patching',
    badgeClass: 'bg-teal-500/10 text-teal-500 border-teal-500/20',
    title: 'Keep Browser & OS Updated',
    desc: 'Older Chrome/Android versions have unpatched zero-day vulnerabilities exploited by phishing kits.'
  }
];

export default function PreventionTips({ score = 0, riskLevel = 'LOW', attackType = '' }) {
  const normalizedScore = Math.max(0, Math.min(100, score));

  const isHigh = normalizedScore >= 70 || riskLevel === 'HIGH';
  const isMedium = (normalizedScore >= 40 && normalizedScore < 70) || riskLevel === 'MEDIUM';

  const typeLower = (attackType || '').toLowerCase();
  const isEmail = typeLower.includes('email');
  const isSmsOrPhone = typeLower.includes('sms') || typeLower.includes('phone') || typeLower.includes('call');
  const isWebsite = typeLower.includes('url') || typeLower.includes('website');

  // Filter tips by threat level
  let filtered = ALL_TIPS.filter((tip) => {
    if (isHigh) return tip.tag.includes('high');
    if (isMedium) return tip.tag.includes('medium') || tip.tag.includes('all');
    return tip.tag.includes('low') || tip.tag.includes('all');
  });

  // Prioritize attack type matching tips first
  filtered.sort((a, b) => {
    let aMatch = 0;
    let bMatch = 0;

    if (isEmail) {
      if (a.tag.includes('email')) aMatch += 2;
      if (b.tag.includes('email')) bMatch += 2;
    }
    if (isSmsOrPhone) {
      if (a.tag.includes('sms') || a.tag.includes('phone')) aMatch += 2;
      if (b.tag.includes('sms') || b.tag.includes('phone')) bMatch += 2;
    }
    if (isWebsite) {
      if (a.tag.includes('website')) aMatch += 2;
      if (b.tag.includes('website')) bMatch += 2;
    }

    return bMatch - aMatch;
  });

  // Display 6 tips max
  const displayTips = filtered.slice(0, 6);

  // Section Header Title
  const getHeaderTitle = () => {
    if (isHigh) return `Critical Action Steps - High Risk Threat (${normalizedScore}/100)`;
    if (isMedium) return `Caution Guidelines for Suspicious Content (${normalizedScore}/100)`;
    return `Stay Safe - Good Security Habits (${normalizedScore}/100)`;
  };

  return (
    <section id="prevention-tips" className="w-full my-8 scroll-mt-24 space-y-6">
      {/* Dynamic Section Header */}
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-cyan-500" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-[var(--text-main)] tracking-tight">
              {getHeaderTitle()}
            </h2>
            <p className="text-xs text-[var(--text-muted)]">
              Contextual safety recommendations based on your threat scan results
            </p>
          </div>
        </div>

        <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
          isHigh
            ? 'bg-rose-500/10 text-rose-500 border-rose-500/20'
            : isMedium
            ? 'bg-amber-500/10 text-amber-500 border-amber-500/20'
            : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
        }`}>
          {isHigh ? '🚨 Critical' : isMedium ? '⚠️ Caution' : '✅ Verified'}
        </span>
      </div>

      {/* Contextual Filtered Tips 3-Column Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6">
        {displayTips.map((tip) => {
          const Icon = tip.icon;
          return (
            <div
              key={tip.id}
              className="bg-[var(--bg-card)] p-5 rounded-2xl border border-[var(--border)] hover:border-cyan-500/40 transition-all duration-300 group hover:-translate-y-1 shadow-sm flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className={`w-11 h-11 rounded-xl ${tip.iconBg} border flex items-center justify-center transition-transform group-hover:scale-105`}>
                    <Icon className={`w-5.5 h-5.5 ${tip.iconColor}`} />
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${tip.badgeClass}`}>
                    {tip.badgeText}
                  </span>
                </div>

                <h3 className="text-base font-bold text-[var(--text-main)] mb-2 group-hover:text-cyan-500 transition-colors">
                  {tip.title}
                </h3>
                <p className="text-xs md:text-sm text-[var(--text-muted)] leading-relaxed">
                  {tip.desc}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-[var(--border)] flex items-center justify-between text-xs text-[var(--text-muted)]">
                <span>Rule #{tip.id}</span>
                <span className="text-cyan-500 font-medium">PhishGuard Intelligence</span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
