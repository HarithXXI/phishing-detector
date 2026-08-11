export function detectInputType(text) {
  if (!text || typeof text !== 'string') return 'phishing';
  const t = text.trim();
  if (!t) return 'phishing';

  // Phone regex - international + Indian
  const phoneRegex = /^(\+?\d{1,4}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}$|\+91[6-9]\d{9}|^\+?\d{10,15}$/;
  const hasOnlyPhone = /^[\d\s+\-()]+$/.test(t) && t.replace(/\D/g, '').length >= 10 && t.replace(/\D/g, '').length <= 15;
  const urlRegex = /(https?:\/\/|www\.|\.com|\.in|\.org|\.net|\.io)/i;
  const emailRegex = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;

  if (hasOnlyPhone && !urlRegex.test(t) && !emailRegex.test(t) && t.length < 20) {
    return 'phone';
  }
  if (phoneRegex.test(t) && t.split(/\s+/).length === 1 && t.length < 20) {
    return 'phone';
  }
  return 'phishing';
}
