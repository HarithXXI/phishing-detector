import React from 'react';

export const DnsCard = ({ dns = {} }) => {
  if (!dns) return null;

  const risk = dns.risk ?? 0;
  const status = dns.status || 'Unknown';

  const riskBadgeClass =
    risk >= 30
      ? 'bg-red-900/40 text-red-300 border border-red-700/50'
      : risk >= 10
      ? 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50'
      : 'bg-green-900/40 text-green-300 border border-green-700/50';

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 shadow-lg text-gray-200">
      <div className="flex justify-between items-center mb-3">
        <span className="text-xs font-bold tracking-wider text-gray-400 uppercase">
          DNS & EMAIL RECORDS
        </span>
        <span className={`text-xs px-2 py-1 rounded font-semibold ${riskBadgeClass}`}>
          {status}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="p-2 rounded bg-gray-800/60 border border-gray-700/50">
          A Record:{' '}
          {dns.A_valid ? (
            <span className="text-green-400 font-semibold">✓ Valid {dns.A?.[0]}</span>
          ) : (
            <span className="text-red-400 font-semibold">✗ None</span>
          )}
        </div>
        <div className="p-2 rounded bg-gray-800/60 border border-gray-700/50">
          MX Server:{' '}
          {dns.MX_valid ? (
            <span className="text-green-400 font-semibold">✓ {dns.MX?.[0]}</span>
          ) : (
            <span className="text-yellow-400 font-semibold">○ None</span>
          )}
        </div>
        <div className="p-2 rounded bg-gray-800/60 border border-gray-700/50">
          SPF Record:{' '}
          {dns.SPF_pass ? (
            <span className="text-green-400 font-semibold">✓ Pass</span>
          ) : (
            <span className="text-red-400 font-semibold">✗ None</span>
          )}
        </div>
        <div className="p-2 rounded bg-gray-800/60 border border-gray-700/50">
          DMARC:{' '}
          {dns.DMARC_protected ? (
            <span className="text-green-400 font-semibold">✓ Protected</span>
          ) : (
            <span className="text-yellow-400 font-semibold">○ None</span>
          )}
        </div>
      </div>
    </div>
  );
};

export default DnsCard;
