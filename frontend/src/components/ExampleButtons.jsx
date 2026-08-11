import React from 'react';
import { Zap } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export const ExampleButtons = ({ onSelectExample }) => {
  const { t } = useTranslation();

  const examples = [
    {
      key: 'try_paypal',
      label: t('try_paypal'),
      text: 'Dear customer, your PayPal account has been locked. Verify at http://paypal-secure-login.tk/login',
    },
    {
      key: 'try_sms',
      label: t('try_sms'),
      text: 'Your SBI account blocked. Update KYC now: http://sbi-kyc-update.xyz',
    },
    {
      key: 'try_email',
      label: t('try_email'),
      text: 'Your Amazon order #123 failed. Click here to update payment: http://amazon-billing-update.com',
    },
  ];

  return (
    <div className="flex flex-wrap items-center gap-2 pt-2">
      <span className="text-xs font-semibold text-[var(--text-muted)] flex items-center gap-1 mr-1">
        <Zap className="w-3.5 h-3.5 text-cyan-500" />
        {t('examples')}
      </span>
      {examples.map((item, index) => (
        <button
          key={index}
          type="button"
          onClick={() => onSelectExample(item.text)}
          className="px-3 py-1.5 rounded-xl bg-[var(--bg-card)] hover:bg-cyan-500/10 border border-[var(--border)] hover:border-cyan-500/40 text-xs font-medium text-[var(--text-main)] hover:text-cyan-500 transition-all duration-200 cursor-pointer shadow-sm"
        >
          {item.label}
        </button>
      ))}
    </div>
  );
};

export default ExampleButtons;
