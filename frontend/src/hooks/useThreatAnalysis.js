import { useState } from 'react';
import { analyzeThreat, analyzeImage } from '../services/api';

export const useThreatAnalysis = () => {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [extractedText, setExtractedText] = useState('');

  const runAnalysis = async (input, file = null) => {
    setLoading(true);
    setError(null);
    try {
      let res = null;
      if (file) {
        res = await analyzeImage(file, typeof input === 'string' ? input : '');
        if (res.extracted_text) {
          setExtractedText(res.extracted_text);
        }
      } else if (typeof input === 'string' && input.trim()) {
        res = await analyzeThreat(input.trim());
      } else {
        throw new Error('Please enter text/URL or attach a screenshot to analyze.');
      }

      if (res.error) {
        throw new Error(res.error);
      }

      setResult(res);
    } catch (err) {
      console.error('[useThreatAnalysis Error]:', err);
      setError(err.message || 'An unexpected error occurred during threat analysis.');
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setResult(null);
    setError(null);
    setLoading(false);
    setExtractedText('');
  };

  return {
    result,
    loading,
    error,
    extractedText,
    runAnalysis,
    reset,
  };
};
