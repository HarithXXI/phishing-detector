import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        toggle();
      }}
      className="w-10 h-10 rounded-xl flex items-center justify-center bg-[var(--bg-card)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-main)] hover:border-cyan-500/40 transition-all duration-200 shadow-sm group cursor-pointer focus:outline-none"
      title={`Switch to ${isDark ? 'Light' : 'Dark'} mode`}
      aria-label="Toggle theme"
    >
      {isDark ? (
        <Sun className="w-4.5 h-4.5 text-amber-400 group-hover:rotate-45 group-hover:scale-110 transition-transform duration-300" />
      ) : (
        <Moon className="w-4.5 h-4.5 text-slate-700 group-hover:-rotate-12 group-hover:scale-110 transition-transform duration-300" />
      )}
    </button>
  );
}
