import { useState } from 'react';
import { analyzeThreat, analyzeImage } from '../services/api';
import { detectInputType } from '../utils/detectType';

export const useThreatAnalysis = () => {
  const [result, setResult] = useState(null);
  const [phoneResult, setPhoneResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [extractedText, setExtractedText] = useState('');

  const runAnalysis = async (input, file = null, forcedType = null) => {
    setLoading(true);
    setError(null);
    try {
      const text = typeof input === 'string' ? input.trim() : '';
      const type = forcedType || detectInputType(text);

      if (type === 'phone' && !file && text) {
        const res = await fetch('/api/phone-intel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone: text })
        });
        const data = await res.json();
        if (data.error) {
          throw new Error(data.error);
        }
        setPhoneResult(data);
        setResult(null);
      } else {
        let res = null;
        if (file) {
          res = await analyzeImage(file, text);
          if (res.extracted_text) {
            setExtractedText(res.extracted_text);
          }
        } else if (text) {
          res = await analyzeThreat(text);
        } else {
          throw new Error('Please enter text/URL or attach a screenshot to analyze.');
        }

        if (res.error) {
          throw new Error(res.error);
        }

        setResult(res);
        setPhoneResult(null);
      }
    } catch (err) {
      console.error('[useThreatAnalysis Error]:', err);
      setError(err.message || 'An unexpected error occurred during threat analysis.');
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setResult(null);
    setPhoneResult(null);
    setError(null);
    setLoading(false);
    setExtractedText('');
  };

  return {
    result,
    phoneResult,
    loading,
    error,
    extractedText,
    runAnalysis,
    reset,
  };
};
