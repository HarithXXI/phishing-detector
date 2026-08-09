import React from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, ExternalLink } from 'lucide-react';

export default function DisclaimerBox({ score = 0, riskLevel = 'LOW' }) {
  const normalizedScore = Math.max(0, Math.min(100, score));

  const isHigh = normalizedScore >= 70 || riskLevel === 'HIGH';
  const isMedium = (normalizedScore >= 40 && normalizedScore < 70) || riskLevel === 'MEDIUM';

  const getCardConfig = () => {
    if (isHigh) {
      return {
        bg: 'bg-rose-500/10 dark:bg-rose-950/30',
        border: 'border-rose-500/30 dark:border-rose-500/40',
        iconBg: 'bg-rose-500/20 border-rose-500/30',
        iconColor: 'text-rose-500',
        titleColor: 'text-rose-600 dark:text-rose-300',
        textColor: 'text-rose-700 dark:text-rose-200',
        icon: ShieldAlert,
        title: 'High Risk Detected - Do Not Proceed',
        text: `This content shows strong phishing indicators (score ${normalizedScore}/100). Do NOT click links, do NOT share OTPs or credentials. If you already clicked or shared data, change passwords immediately and report to cybercrime.gov.in / 1930 within 1 hour.`
      };
    }

    if (isMedium) {
      return {
        bg: 'bg-amber-500/10 dark:bg-amber-950/30',
        border: 'border-amber-500/30 dark:border-amber-500/40',
        iconBg: 'bg-amber-500/20 border-amber-500/30',
        iconColor: 'text-amber-500',
        titleColor: 'text-amber-600 dark:text-amber-300',
        textColor: 'text-amber-800 dark:text-amber-200',
        icon: AlertTriangle,
        title: 'Suspicious - Verify Before Action',
        text: `Score ${normalizedScore}/100 - Suspicious patterns found. Verify sender via official app/website, don't use links in message. When in doubt, call official customer support numbers directly.`
      };
    }

    return {
      bg: 'bg-emerald-500/10 dark:bg-emerald-950/30',
      border: 'border-emerald-500/30 dark:border-emerald-500/40',
      iconBg: 'bg-emerald-500/20 border-emerald-500/30',
      iconColor: 'text-emerald-500',
      titleColor: 'text-emerald-600 dark:text-emerald-300',
      textColor: 'text-emerald-800 dark:text-emerald-200',
      icon: CheckCircle2,
      title: 'Low Risk - Still Stay Alert',
      text: `Score ${normalizedScore}/100 - No major threat indicators found, but phishing tactics evolve daily. Always double-check URLs and sender headers. Use PhishGuard for every suspicious message.`
    };
  };

  const config = getCardConfig();
  const IconComponent = config.icon;

  return (
    <div className={`w-full ${config.bg} border ${config.border} rounded-2xl p-5 backdrop-blur-md flex flex-col sm:flex-row items-start gap-4 relative transition-all duration-300 shadow-sm group`}>
      {/* Dynamic Status Icon */}
      <div className={`w-11 h-11 rounded-xl ${config.iconBg} border flex items-center justify-center shrink-0 mt-0.5 shadow-sm`}>
        <IconComponent className={`w-6 h-6 ${config.iconColor}`} />
      </div>

      {/* Main Contextual Content */}
      <div className="flex-1 space-y-2">
        <h4 className={`text-base font-bold ${config.titleColor} tracking-wide flex items-center space-x-2`}>
          <span>{config.title}</span>
        </h4>
        <p className={`text-xs md:text-sm ${config.textColor} leading-relaxed`}>
          {config.text}
        </p>

        <div className="pt-1 flex items-center space-x-3">
          <a
            href="https://cybercrime.gov.in/"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold text-amber-700 dark:text-amber-300 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 transition-colors shadow-sm"
          >
            <span>Official CyberCrime Portal (cybercrime.gov.in)</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>
    </div>
  );
}
