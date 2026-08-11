import React from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';

export const ThreatMeter = ({ score = 0, riskLevel = 'LOW' }) => {
  // Normalize score between 0 and 100
  const normalizedScore = Math.max(0, Math.min(100, score));
  
  // Calculate rotation angle for needle (-90 deg to +90 deg)
  const needleRotation = -90 + (normalizedScore / 100) * 180;

  const getStatusColor = () => {
    if (normalizedScore >= 81 || riskLevel === 'CRITICAL') {
      return {
        text: 'text-red-400',
        bg: 'bg-red-600/10',
        border: 'border-red-600/30',
        gradient: 'from-red-600 to-red-800',
        shadow: 'shadow-red-600/20',
        badge: 'bg-red-600/20 text-red-300 border-red-600/40',
        label: 'CRITICAL',
        icon: ShieldAlert,
      };
    }
    if (normalizedScore >= 61 || riskLevel === 'HIGH') {
      return {
        text: 'text-rose-400',
        bg: 'bg-rose-500/10',
        border: 'border-rose-500/30',
        gradient: 'from-rose-500 to-red-600',
        shadow: 'shadow-rose-500/20',
        badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
        label: 'HIGH RISK',
        icon: ShieldAlert,
      };
    }
    if (normalizedScore >= 31 || riskLevel === 'MEDIUM') {
      return {
        text: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/30',
        gradient: 'from-amber-400 to-orange-500',
        shadow: 'shadow-amber-500/20',
        badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        label: 'MEDIUM RISK',
        icon: AlertTriangle,
      };
    }
    return {
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      gradient: 'from-emerald-400 to-teal-500',
      shadow: 'shadow-emerald-500/20',
      badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      label: 'LOW RISK',
      icon: CheckCircle2,
    };
  };

  const status = getStatusColor();
  const IconComponent = status.icon;

  return (
    <div className="flex flex-col items-center justify-center p-6 rounded-2xl bg-[var(--bg-card)] border border-[var(--border)] shadow-[var(--shadow)] relative overflow-hidden">
      {/* Background Subtle Glow */}
      <div className={`absolute -top-10 left-1/2 -translate-x-1/2 w-48 h-48 rounded-full blur-3xl opacity-20 pointer-events-none bg-gradient-to-br ${status.gradient}`} />

      {/* Title */}
      <div className="flex items-center space-x-2 mb-4">
        <IconComponent className={`w-5 h-5 ${status.text}`} />
        <span className="text-sm font-semibold tracking-wider uppercase text-[var(--text-muted)]">
          Threat Risk Gauge
        </span>
      </div>

      {/* Half-Arc Gauge SVG Container */}
      <div className="relative w-64 h-36 flex justify-center items-end">
        <svg className="w-full h-full" viewBox="0 0 200 110">
          <defs>
            <linearGradient id="arcGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="50%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#f43f5e" />
            </linearGradient>
          </defs>

          {/* Background Arc Track */}
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="16"
            strokeLinecap="round"
          />

          {/* Colored Arc Gradient Track */}
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke="url(#arcGradient)"
            strokeWidth="14"
            strokeLinecap="round"
            opacity="0.9"
          />
        </svg>

        {/* Animated Needle Pointer */}
        <motion.div
          className="absolute bottom-1.5 left-1/2 w-1.5 h-24 bg-gradient-to-t from-slate-200 to-white rounded-full origin-bottom shadow-lg z-10"
          initial={{ rotate: -90 }}
          animate={{ rotate: needleRotation }}
          transition={{ type: 'spring', stiffness: 60, damping: 15 }}
          style={{ translateX: '-50%' }}
        />

        {/* Center Cap Pivot */}
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-6 h-6 rounded-full bg-slate-900 border-2 border-white shadow-xl z-20 flex items-center justify-center">
          <div className="w-2 h-2 rounded-full bg-cyan-400" />
        </div>
      </div>

      {/* Score Number Display */}
      <div className="mt-4 text-center">
        <motion.div
          className="text-4xl font-extrabold tracking-tight text-white flex items-baseline justify-center space-x-1"
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.4 }}
        >
          <span>{normalizedScore}</span>
          <span className="text-lg font-medium text-slate-400">%</span>
        </motion.div>

        {/* Risk Level Badge */}
        <div className="mt-2 inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-bold border tracking-wider uppercase shadow-md">
          <span className={`px-3 py-0.5 rounded-full border ${status.badge}`}>
            {status.label}
          </span>
        </div>
      </div>
    </div>
  );
};

export default ThreatMeter;
