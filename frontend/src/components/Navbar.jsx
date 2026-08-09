import React, { useState, useRef, useEffect } from 'react';
import { Shield, ExternalLink, Menu, X, Globe, ChevronDown, Search, Check } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import ThemeToggle from './ThemeToggle';
import { LANGUAGES } from '../i18n';

export const Navbar = ({ sidebarOpen, setSidebarOpen }) => {
  const { t, i18n } = useTranslation();
  const [langOpen, setLangOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef(null);

  const currentCode = (i18n.language || 'en').split('-')[0];
  const activeLang = LANGUAGES.find((l) => l.code === currentCode) || LANGUAGES[0];

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setLangOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelectLang = (lang) => {
    i18n.changeLanguage(lang.code);
    document.documentElement.dir = lang.rtl ? 'rtl' : 'ltr';
    setLangOpen(false);
    setSearchQuery('');
  };

  const filteredLanguages = LANGUAGES.filter(
    (l) =>
      l.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      l.native.toLowerCase().includes(searchQuery.toLowerCase()) ||
      l.code.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <header className="sticky top-0 z-30 w-full border-b border-[var(--border)] bg-[var(--bg-sidebar)] text-[var(--text-main)] backdrop-blur-md transition-colors duration-300 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
        
        {/* Left Side: Hamburger Menu + Logo */}
        <div className="flex items-center space-x-3.5">
          {/* Hamburger Menu Toggle Button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSidebarOpen(!sidebarOpen);
            }}
            className="w-10 h-10 rounded-xl bg-[var(--bg-card)] flex items-center justify-center border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-main)] hover:border-cyan-400/50 transition-all shadow-sm group focus:outline-none cursor-pointer"
            title={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            aria-label="Toggle navigation menu"
          >
            {sidebarOpen ? (
              <X className="w-5 h-5 text-cyan-500 group-hover:rotate-90 transition-transform duration-200" />
            ) : (
              <Menu className="w-5 h-5 text-[var(--text-muted)] group-hover:text-cyan-500 transition-colors" />
            )}
          </button>

          {/* Brand Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Shield className="w-6 h-6 text-white" />
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-400"></span>
              </span>
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-tight text-[var(--text-main)]">
                  {t('brand')} <span className="text-cyan-500 font-extrabold text-xs uppercase px-2 py-0.5 rounded-md bg-cyan-500/10 border border-cyan-500/20 ml-1">{t('live')}</span>
                </h1>
              </div>
              <p className="text-xs text-[var(--text-muted)] hidden sm:block">
                Multi-layer threat intelligence & AI security engine
              </p>
            </div>
          </div>
        </div>

        {/* Right Side: World Language Selector + Theme Toggle + Report Fraud Link */}
        <div className="flex items-center space-x-2.5">
          {/* World Language Selector Dropdown */}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setLangOpen(!langOpen);
              }}
              className="flex items-center space-x-2 px-3 py-2 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] text-xs font-semibold text-[var(--text-main)] hover:border-cyan-500/40 transition-all shadow-sm cursor-pointer"
              title="Select World Language"
            >
              <span className="text-base leading-none">{activeLang.flag}</span>
              <span className="hidden md:inline font-medium">{activeLang.native}</span>
              <ChevronDown className={`w-3.5 h-3.5 text-[var(--text-muted)] transition-transform duration-200 ${langOpen ? 'rotate-180' : ''}`} />
            </button>

            {/* Dropdown Menu */}
            {langOpen && (
              <div
                onClick={(e) => e.stopPropagation()}
                className="absolute right-0 mt-2 w-80 max-h-80 bg-[var(--bg-sidebar)] border border-[var(--border)] rounded-2xl shadow-2xl z-50 flex flex-col overflow-hidden backdrop-blur-xl animate-in zoom-in-95 duration-150"
              >
                {/* Search Bar */}
                <div className="p-2.5 border-b border-[var(--border)] bg-[var(--bg-card)]">
                  <div className="relative flex items-center">
                    <Search className="w-4 h-4 absolute left-3 text-[var(--text-muted)]" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder={t('search_language') || 'Search language...'}
                      className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)] text-xs text-[var(--text-main)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500 transition-all"
                    />
                  </div>
                </div>

                {/* Language Item List */}
                <div className="flex-1 overflow-y-auto p-1.5 space-y-0.5">
                  {filteredLanguages.length > 0 ? (
                    filteredLanguages.map((lang) => {
                      const isSelected = lang.code === activeLang.code;
                      return (
                        <button
                          key={lang.code}
                          onClick={() => handleSelectLang(lang)}
                          className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs transition-colors cursor-pointer ${
                            isSelected
                              ? 'bg-cyan-500/10 text-cyan-500 font-bold border border-cyan-500/20'
                              : 'hover:bg-[var(--bg-card)] text-[var(--text-main)] font-medium'
                          }`}
                        >
                          <div className="flex items-center space-x-2.5">
                            <span className="text-base">{lang.flag}</span>
                            <span className="font-semibold">{lang.native}</span>
                            {lang.native !== lang.name && (
                              <span className="text-[11px] text-[var(--text-muted)]">({lang.name})</span>
                            )}
                          </div>
                          {isSelected && <Check className="w-4 h-4 text-cyan-500" />}
                        </button>
                      );
                    })
                  ) : (
                    <div className="p-4 text-center text-xs text-[var(--text-muted)]">
                      No language found matching "{searchQuery}"
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <ThemeToggle />

          <a
            href="https://cybercrime.gov.in/login"
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-amber-600 dark:text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 transition-all shadow-sm"
            title="Report cyber fraud directly to official government portal"
          >
            <span className="hidden lg:inline">Report fraud to cybercrime.gov.in</span>
            <span className="lg:hidden">Report 🚨</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
