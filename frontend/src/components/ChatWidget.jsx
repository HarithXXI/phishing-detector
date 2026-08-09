import React, { useState, useRef, useEffect } from 'react';
import { Shield, X, Send, Bot, Copy, Check, Sparkles, Mic, MicOff } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { useTranslation } from 'react-i18next';
import { sendChatMessage } from '../services/api';
import { LANGUAGES } from '../i18n';

const QUESTION_POOLS = {
  email: [
    'How to check email SPF & DKIM records?',
    'What is a fake sender domain spoofing?',
    'How to inspect raw email headers in Gmail?',
    'How to report email phishing to cybercrime.gov.in?',
    'Can images in emails contain malicious trackers?',
    'What is spear phishing vs mass phishing?'
  ],
  sms: [
    'Why banks never ask for OTP via SMS?',
    'How to report SMS fraud to 1930 helpline?',
    'Why Google Authenticator is safer than SMS 2FA?',
    'What is SIM swapping and how to prevent it?',
    'How to block scam sender IDs on Android/iOS?',
    'What are fake lottery & reward SMS scams?'
  ],
  url: [
    'How to check WHOIS domain creation date?',
    'What is a typo-squatted domain like paypaI.com?',
    'How to long-press to preview links on mobile?',
    'Why free HTTPS certificates do not mean a website is safe?',
    'What is IP address URL masking?',
    'How to use VirusTotal to scan suspicious links?'
  ],
  general: [
    'How to spot psychological urgency in scams?',
    'What to do within the 1-Hour Golden Hour after fraud?',
    'How to check if my email was leaked in a data breach?',
    'What is voice phishing (vishing) and AI voice cloning?',
    'How to secure UPI / GPay / PhonePe from QR code scams?',
    'What is ransomware and how do phishing emails drop it?'
  ]
};

const getFreshSuggestions = (queryText, replyText, messages) => {
  const combined = ((queryText || '') + ' ' + (replyText || '')).toLowerCase();

  const usedQuestions = new Set();
  messages.forEach((m) => {
    if (m.text) usedQuestions.add(m.text.toLowerCase());
    if (m.suggestions) {
      m.suggestions.forEach((s) => usedQuestions.add(s.toLowerCase()));
    }
  });

  let primaryCategory = 'general';
  if (combined.includes('email') || combined.includes('header') || combined.includes('spf') || combined.includes('gmail')) {
    primaryCategory = 'email';
  } else if (combined.includes('sms') || combined.includes('otp') || combined.includes('phone') || combined.includes('smishing') || combined.includes('bank')) {
    primaryCategory = 'sms';
  } else if (combined.includes('url') || combined.includes('link') || combined.includes('website') || combined.includes('domain') || combined.includes('http')) {
    primaryCategory = 'url';
  }

  const candidatePool = [
    ...(QUESTION_POOLS[primaryCategory] || []),
    ...QUESTION_POOLS.general,
    ...QUESTION_POOLS.email,
    ...QUESTION_POOLS.sms,
    ...QUESTION_POOLS.url
  ];

  const unused = candidatePool.filter((q) => !usedQuestions.has(q.toLowerCase()));
  const uniqueCandidates = Array.from(new Set(unused));

  for (let i = uniqueCandidates.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [uniqueCandidates[i], uniqueCandidates[j]] = [uniqueCandidates[j], uniqueCandidates[i]];
  }

  return uniqueCandidates.slice(0, 3);
};

export const ChatWidget = () => {
  const { t, i18n } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      id: 1,
      sender: 'bot',
      text: "👋 Hi! I'm **PhishGuard AI Assistant**.\nAsk me about phishing indicators, suspicious links, smishing, or security verification.",
      isStreaming: false,
      suggestions: ['Is this URL safe?', 'How to spot phishing emails?', 'What is social engineering?'],
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  // Speech-to-Text state & ref
  const [isListening, setIsListening] = useState(false);
  const recognitionRef = useRef(null);

  const messagesEndRef = useRef(null);
  const streamIntervalRef = useRef(null);

  const currentCode = (i18n.language || 'en').split('-')[0];
  const activeLang = LANGUAGES.find((l) => l.code === currentCode) || LANGUAGES[0];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  useEffect(() => {
    return () => {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current);
      }
    };
  }, []);

  // Web Speech API Toggle Function
  const toggleListening = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      alert(t('use_chrome') || 'Voice input needs Chrome/Edge');
      return;
    }

    if (isListening) {
      recognitionRef.current?.stop();
      setIsListening(false);
      return;
    }

    const recognition = new SpeechRecognition();
    recognitionRef.current = recognition;

    const langMap = {
      en: 'en-US', hi: 'hi-IN', bn: 'bn-BD', zh: 'zh-CN', es: 'es-ES', ar: 'ar-SA',
      fr: 'fr-FR', pt: 'pt-BR', ru: 'ru-RU', ur: 'ur-PK', id: 'id-ID', de: 'de-DE',
      ja: 'ja-JP', ko: 'ko-KR', tr: 'tr-TR', vi: 'vi-VN', it: 'it-IT', ta: 'ta-IN',
      te: 'te-IN', mr: 'mr-IN', gu: 'gu-IN', pl: 'pl-PL', uk: 'uk-UA', nl: 'nl-NL',
      fa: 'fa-IR', th: 'th-TH', ms: 'ms-MY', sw: 'sw-KE', ha: 'ha-NG', am: 'am-ET'
    };

    recognition.lang = langMap[currentCode] || 'en-US';
    recognition.interimResults = true;
    recognition.continuous = false;

    recognition.onstart = () => setIsListening(true);
    recognition.onend = () => setIsListening(false);
    recognition.onerror = () => setIsListening(false);

    recognition.onresult = (e) => {
      const transcript = e.results[0][0].transcript;
      setInputText(transcript);
    };

    recognition.start();
  };

  const handleCopyText = (id, text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSend = async (textToSend = null) => {
    const queryText = (textToSend || inputText).trim();
    if (!queryText || isSending) return;

    const userMsgId = Date.now();
    const botMsgId = Date.now() + 1;

    const userMessage = {
      id: userMsgId,
      sender: 'user',
      text: queryText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [
      ...prev,
      userMessage,
      {
        id: botMsgId,
        sender: 'bot',
        text: '',
        isStreaming: true,
        suggestions: [],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);

    setInputText('');
    setIsSending(true);

    try {
      const systemInstruction = `[System instruction: Answer like ChatGPT: clear, helpful, concise, using markdown bullets and bold formatting. Reply in ${activeLang.native} language.]\n\nUser Question: ${queryText}`;
      const response = await sendChatMessage(systemInstruction);
      const fullReply = response.reply || `I analyzed your query regarding "${queryText}". Always verify suspicious links and requests with official sources.`;

      const words = fullReply.split(' ');
      let currentWordIndex = 0;
      let streamedText = '';

      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current);

      streamIntervalRef.current = setInterval(() => {
        if (currentWordIndex < words.length) {
          streamedText += (currentWordIndex === 0 ? '' : ' ') + words[currentWordIndex];
          currentWordIndex++;

          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === botMsgId
                ? { ...msg, text: streamedText, isStreaming: currentWordIndex < words.length }
                : msg
            )
          );
        } else {
          clearInterval(streamIntervalRef.current);
          setIsSending(false);

          // Generate fresh non-repeating suggestive follow-up questions
          setMessages((prev) => {
            const freshSuggs = getFreshSuggestions(queryText, fullReply, prev);
            return prev.map((msg) =>
              msg.id === botMsgId
                ? { ...msg, suggestions: freshSuggs }
                : msg
            );
          });
        }
      }, 30);
    } catch (err) {
      console.error('[ChatWidget Error]:', err);
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current);

      const fallbackText = `🛡️ **PhishGuard AI** (${activeLang.native})\n\nAlways verify unrequested emails or messages directly through official apps. If you suspect fraud, report to **1930** or [cybercrime.gov.in/login](https://cybercrime.gov.in/login).`;

      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === botMsgId
            ? {
                ...msg,
                text: fallbackText,
                isStreaming: false,
                suggestions: ['How to check domain WHOIS?', 'Report fraud to cybercrime.gov.in']
              }
            : msg
        )
      );
      setIsSending(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <>
      {/* Floating Launcher Button */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          setIsOpen(!isOpen);
        }}
        className="fixed bottom-6 right-6 w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-blue-600 text-white flex items-center justify-center shadow-2xl shadow-cyan-500/30 hover:scale-105 transition-all duration-300 z-40 group cursor-pointer"
        title="Open PhishGuard AI Assistant"
        aria-label="Open chat widget"
      >
        {isOpen ? (
          <X className="w-6 h-6 text-white" />
        ) : (
          <div className="relative flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-300 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-300"></span>
            </span>
          </div>
        )}
      </button>

      {/* Floating OpenAI ChatGPT-style Window */}
      {isOpen && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="fixed bottom-24 right-6 w-[380px] max-w-[calc(100vw-3rem)] h-[520px] bg-[var(--bg-card)] backdrop-blur-xl border border-[var(--border)] rounded-2xl shadow-2xl z-50 flex flex-col overflow-hidden animate-in zoom-in-95 duration-200"
        >
          {/* Header */}
          <div className="p-4 bg-gradient-to-r from-cyan-600/95 via-cyan-500/95 to-blue-600/95 backdrop-blur-md text-white flex items-center justify-between shadow-md">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-xl bg-white/20 backdrop-blur-sm flex items-center justify-center border border-white/20">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h4 className="text-sm font-bold leading-tight">{t('chat_title') || 'PhishGuard AI'}</h4>
                <p className="text-[10px] text-cyan-100 flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-cyan-200" /> {t('chat_sub') || 'Team BYTE-BUILDERS'} ({activeLang.native})
                </p>
              </div>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="p-1 rounded-lg hover:bg-white/20 transition-colors text-white cursor-pointer"
              title="Close chat"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Messages Feed Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-[var(--bg-main)]/50 backdrop-blur-md">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
              >
                {/* Message Bubble Container */}
                <div className="flex items-start space-x-2 max-w-[88%]">
                  {msg.sender === 'bot' && (
                    <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center shrink-0 mt-0.5 shadow-sm">
                      <Shield className="w-4 h-4 text-cyan-500" />
                    </div>
                  )}

                  <div
                    className={`relative rounded-2xl px-4 py-2.5 text-xs leading-relaxed shadow-sm ${
                      msg.sender === 'user'
                        ? 'bg-blue-600 text-white rounded-br-sm ml-auto'
                        : 'bg-[var(--bg-input)] text-[var(--text-main)] border border-[var(--border)] rounded-bl-sm'
                    }`}
                  >
                    {/* Bot Content with ReactMarkdown or Typing Bouncing Dots */}
                    {msg.sender === 'bot' ? (
                      msg.text === '' && msg.isStreaming ? (
                        <div className="flex items-center space-x-1.5 py-1 px-1">
                          <span className="w-2 h-2 rounded-full bg-cyan-500 animate-bounce" style={{ animationDelay: '0ms' }}></span>
                          <span className="w-2 h-2 rounded-full bg-cyan-500 animate-bounce" style={{ animationDelay: '150ms' }}></span>
                          <span className="w-2 h-2 rounded-full bg-cyan-500 animate-bounce" style={{ animationDelay: '300ms' }}></span>
                        </div>
                      ) : (
                        <div className="markdown-body space-y-1.5 text-xs">
                          <ReactMarkdown>{msg.text}</ReactMarkdown>
                        </div>
                      )
                    ) : (
                      <p className="whitespace-pre-wrap">{msg.text}</p>
                    )}
                  </div>
                </div>

                {/* Suggestive Question Chips */}
                {msg.sender === 'bot' && msg.suggestions && msg.suggestions.length > 0 && !msg.isStreaming && (
                  <div className="mt-2.5 space-y-1.5 w-full pl-9">
                    {msg.suggestions.map((sug, i) => (
                      <button
                        key={i}
                        onClick={() => handleSend(sug)}
                        className="w-full text-left text-[11px] px-3 py-1.5 rounded-xl bg-[var(--bg-card)] hover:bg-cyan-500/10 border border-[var(--border)] hover:border-cyan-500/30 text-cyan-500 transition-colors cursor-pointer shadow-sm"
                      >
                        💡 {sug}
                      </button>
                    ))}
                  </div>
                )}

                {/* Footer metadata: Timestamp + Copy Button for Bot Messages */}
                <div className="flex items-center space-x-2 mt-1 px-1 text-[10px] text-[var(--text-muted)]">
                  <span>{msg.timestamp}</span>
                  {msg.sender === 'bot' && msg.text && !msg.isStreaming && (
                    <button
                      onClick={() => handleCopyText(msg.id, msg.text)}
                      className="hover:text-[var(--text-main)] flex items-center gap-0.5 transition-colors cursor-pointer"
                      title="Copy response"
                    >
                      {copiedId === msg.id ? (
                        <Check className="w-3 h-3 text-emerald-500" />
                      ) : (
                        <Copy className="w-3 h-3 text-[var(--text-muted)]" />
                      )}
                    </button>
                  )}
                </div>
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Area (Textarea + Mic + Send Button) */}
          <div className="p-3 bg-[var(--bg-sidebar)]/90 backdrop-blur-md border-t border-[var(--border)]">
            {/* Listening Banner Animation */}
            {isListening && (
              <div className="flex items-center gap-2 px-3 py-2 text-xs text-red-500 bg-red-50 dark:bg-red-950/20 rounded-lg mb-2">
                <span className="w-2 h-2 bg-red-500 rounded-full animate-ping"></span>
                <span>Listening in {activeLang?.native || 'English'}...</span>
                <div className="flex gap-0.5 ml-2">
                  <span className="w-0.5 h-3 bg-red-500 animate-[bounce_0.6s_infinite]"></span>
                  <span className="w-0.5 h-4 bg-red-500 animate-[bounce_0.6s_0.2s_infinite]"></span>
                  <span className="w-0.5 h-2 bg-red-500 animate-[bounce_0.6s_0.4s_infinite]"></span>
                </div>
              </div>
            )}

            <div className="flex items-end space-x-2">
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={t('type_message') || 'Type a message...'}
                rows={1}
                className="flex-1 px-3.5 py-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border)] text-xs text-[var(--text-main)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500 transition-all resize-none max-h-24 min-h-[40px] leading-relaxed"
              />

              {/* Minimalist Mic Voice Input Button */}
              <button
                type="button"
                onClick={toggleListening}
                className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all cursor-pointer shrink-0 mb-0.5 ${
                  isListening
                    ? 'bg-rose-500/15 border border-rose-500/30 text-rose-500 animate-pulse shadow-sm shadow-rose-500/20'
                    : 'bg-[var(--bg-input)] border border-[var(--border)] hover:border-cyan-500/40 text-[var(--text-muted)] hover:text-cyan-500'
                }`}
                title={isListening ? 'Stop voice input' : 'Voice input'}
              >
                {isListening ? <MicOff className="w-4 h-4 text-rose-500" /> : <Mic className="w-4 h-4" />}
              </button>

              {/* Send Button */}
              <button
                type="button"
                onClick={() => handleSend()}
                disabled={isSending || !inputText.trim()}
                className="w-10 h-10 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white flex items-center justify-center disabled:opacity-40 transition-all shadow-md shrink-0 cursor-pointer mb-0.5"
                title="Send message"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default ChatWidget;
