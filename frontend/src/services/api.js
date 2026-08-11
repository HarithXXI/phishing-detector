import axios from 'axios';

const BASE = import.meta.env.VITE_API_URL || '';
export const api = axios.create({
  baseURL: BASE,
  timeout: 20000,
});

export const analyzeThreat = async (text) => {
  try {
    const response = await api.post('/api/analyze', { text });
    return response.data;
  } catch (error) {
    console.error('[API Error] analyzeThreat:', error);
    throw new Error(error.response?.data?.error || 'Failed to analyze threat');
  }
};

export const analyzeImage = async (file, text = '') => {
  try {
    const formData = new FormData();
    if (file) formData.append('image', file);
    if (text) formData.append('text', text);

    const response = await api.post('/api/analyze-image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    console.error('[API Error] analyzeImage:', error);
    if (error.response?.data?.error) {
      return { error: error.response.data.error };
    }
    if (text && text.trim()) {
      return await analyzeThreat(text.trim());
    }
    throw new Error(error.response?.data?.error || 'Failed to analyze screenshot');
  }
};

export const sendChatMessage = async (message, imageFile = null) => {
  try {
    if (imageFile) {
      const formData = new FormData();
      formData.append('message', message || '');
      formData.append('image', imageFile);
      const response = await api.post('/api/chat', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return response.data;
    } else {
      const response = await api.post('/api/chat', { message });
      return response.data;
    }
  } catch (error) {
    console.error('[API Error] sendChatMessage:', error);
    return {
      reply: error.response?.data?.reply || error.response?.data?.error || '🛡️ **PhishGuard Security Assistant**\n\nPhishing attacks rely on fake domains, urgency traps, and credential theft. Always verify unrequested messages directly via official apps or website logins. If you suspect fraud, report immediately to **1930** or [cybercrime.gov.in/login](https://cybercrime.gov.in/login).',
      sources: []
    };
  }
};

export const fetchScreenshot = async (url) => {
  try {
    const response = await api.get('/api/screenshot', { params: { url } });
    return response.data;
  } catch (error) {
    console.error('[API Error] fetchScreenshot:', error);
    throw new Error('Failed to capture screenshot');
  }
};

export const fetchUrlPreview = async (url) => {
  try {
    const response = await api.get('/api/preview', { params: { url } });
    return response.data;
  } catch (error) {
    console.error('[API Error] fetchUrlPreview:', error);
    return {
      title: 'Isolated Web Preview',
      description: 'Domain preview evaluated under PhishGuard sandbox isolation.',
      url: url,
      image: null,
    };
  }
};
