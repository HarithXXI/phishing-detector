import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import Backend from 'i18next-http-backend';

export const LANGUAGES = [
  { code: 'en', name: 'English', native: 'English', flag: '🇺🇸' },
  { code: 'zh', name: 'Chinese', native: '中文', flag: '🇨🇳' },
  { code: 'es', name: 'Spanish', native: 'Español', flag: '🇪🇸' },
  { code: 'ar', name: 'Arabic', native: 'العربية', flag: '🇸🇦', rtl: true },
  { code: 'hi', name: 'Hindi', native: 'हिन्दी', flag: '🇮🇳' },
  { code: 'fr', name: 'French', native: 'Français', flag: '🇫🇷' },
  { code: 'pt', name: 'Portuguese', native: 'Português', flag: '🇧🇷' },
  { code: 'bn', name: 'Bengali', native: 'বাংলা', flag: '🇧🇩' },
  { code: 'ru', name: 'Russian', native: 'Русский', flag: '🇷🇺' },
  { code: 'ur', name: 'Urdu', native: 'اردو', flag: '🇵🇰', rtl: true },
  { code: 'id', name: 'Indonesian', native: 'Indonesia', flag: '🇮🇩' },
  { code: 'de', name: 'German', native: 'Deutsch', flag: '🇩🇪' },
  { code: 'ja', name: 'Japanese', native: '日本語', flag: '🇯🇵' },
  { code: 'ko', name: 'Korean', native: '한국어', flag: '🇰🇷' },
  { code: 'tr', name: 'Turkish', native: 'Türkçe', flag: '🇹🇷' },
  { code: 'vi', name: 'Vietnamese', native: 'Tiếng Việt', flag: '🇻🇳' },
  { code: 'it', name: 'Italian', native: 'Italiano', flag: '🇮🇹' },
  { code: 'ta', name: 'Tamil', native: 'தமிழ்', flag: '🇮🇳' },
  { code: 'te', name: 'Telugu', native: 'తెలుగు', flag: '🇮🇳' },
  { code: 'mr', name: 'Marathi', native: 'मराठी', flag: '🇮🇳' },
  { code: 'gu', name: 'Gujarati', native: 'ગુજરાતી', flag: '🇮🇳' },
  { code: 'pl', name: 'Polish', native: 'Polski', flag: '🇵🇱' },
  { code: 'uk', name: 'Ukrainian', native: 'Українська', flag: '🇺🇦' },
  { code: 'nl', name: 'Dutch', native: 'Nederlands', flag: '🇳🇱' },
  { code: 'fa', name: 'Persian', native: 'فارسی', flag: '🇮🇷', rtl: true },
  { code: 'th', name: 'Thai', native: 'ไทย', flag: '🇹🇭' },
  { code: 'ms', name: 'Malay', native: 'Melayu', flag: '🇲🇾' },
  { code: 'sw', name: 'Swahili', native: 'Kiswahili', flag: '🇰🇪' },
  { code: 'ha', name: 'Hausa', native: 'Hausa', flag: '🇳🇬' },
  { code: 'am', name: 'Amharic', native: 'አማርኛ', flag: '🇪🇹' }
];

i18n
  .use(Backend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: 'en',
    supportedLngs: LANGUAGES.map((l) => l.code),
    backend: {
      loadPath: '/locales/{{lng}}/translation.json'
    },
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage']
    },
    react: {
      useSuspense: false
    }
  });

export default i18n;
