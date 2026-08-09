// ==========================================================================
// PhishGuard AI — Floating Chat Widget (Intercom Style)
// ==========================================================================

(function () {
    "use strict";

    const API = "/api/chat";
    const STREAM_API = "/api/chat/stream";
    const MAX_IMG_SIZE = 5 * 1024 * 1024; // 5 MB

    // ---- Inject DOM ----
    function createWidget() {
        const html = `
        <!-- Toggle Button -->
        <button class="cw-toggle" id="chatbot-toggle" aria-label="Open chat">
            <img src="assets/logo.png" class="cw-icon-chat" alt="PhishGuard" style="width: 32px; height: 32px; object-fit: contain; border-radius: 8px;" />
            <svg class="cw-icon-close" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"/>
                <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
        </button>

        <!-- Chat Window -->
        <div class="cw-window" id="cw-window">
            <!-- Header -->
            <div class="cw-header">
                <div class="cw-header-left">
                    <div class="cw-header-icon" style="background:transparent; border-radius:8px; overflow:hidden; width:34px; height:34px;">
                        <img src="assets/chat-logo.png" alt="PhishGuard AI Logo" style="width:100%; height:100%; object-fit:contain;">
                    </div>
                    <div>
                        <div class="cw-header-title">Security Assistant</div>
                        <div class="cw-header-status">
                            <span class="cw-status-dot"></span>
                            Online
                        </div>
                    </div>
                </div>
                <button class="cw-close-btn" id="cw-close" aria-label="Close chat">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>

            <!-- Messages -->
            <div class="cw-messages" id="cw-messages">
                <div class="cw-welcome">
                    <div class="cw-welcome-title">👋 Hi! I'm your Security Assistant</div>
                    <div class="cw-welcome-sub">Ask me about phishing, suspicious links, or email headers for security analysis.</div>
                    <div class="cw-suggestions" id="cw-suggestions">
                        <button class="cw-suggestion" data-msg="Is this URL safe?">Is this URL safe?</button>
                        <button class="cw-suggestion" data-msg="How to spot phishing emails?">Spot phishing emails</button>
                        <button class="cw-suggestion" data-msg="What is social engineering?">Social engineering</button>
                    </div>
                </div>

                <!-- Typing indicator -->
                <div class="cw-typing" id="cw-typing">
                    <span class="cw-typing-dot"></span>
                    <span class="cw-typing-dot"></span>
                    <span class="cw-typing-dot"></span>
                </div>
            </div>

            <!-- Error toast -->
            <div class="cw-error-toast" id="cw-error"></div>

            <!-- Input Area -->
            <div class="cw-input-area">
                <div class="cw-input-row">
                    <input type="text" class="cw-text-input" id="cw-text-input" placeholder="Type a message…" autocomplete="off">
                    <button class="cw-send-btn" id="cw-send-btn" aria-label="Send message">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <line x1="22" y1="2" x2="11" y2="13"/>
                            <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                        </svg>
                    </button>
                </div>
            </div>
        </div>

        <!-- Lightbox -->
        <div class="cw-lightbox" id="cw-lightbox">
            <img id="cw-lightbox-img" src="" alt="expanded">
        </div>
        `;

        const container = document.createElement("div");
        container.id = "cw-root";
        container.innerHTML = html;
        document.body.appendChild(container);
    }

    // ---- Simple Markdown → HTML (no external deps) ----
    function md(text) {
        if (!text) return "";
        let s = text;
        // Escape HTML
        s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        // Headers
        s = s.replace(/^### (.+)$/gm, "<h3>$1</h3>");
        s = s.replace(/^## (.+)$/gm, "<h2>$1</h2>");
        s = s.replace(/^# (.+)$/gm, "<h1>$1</h1>");
        // Bold
        s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
        // Italic
        s = s.replace(/\*(.+?)\*/g, "<em>$1</em>");
        // Inline code
        s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
        // Unordered lists
        s = s.replace(/^[-*] (.+)$/gm, "<li>$1</li>");
        s = s.replace(/(?:<li>.*?<\/li>\s*)+/g, (match) => "<ul>" + match + "</ul>");
        // Clean up nested <ul> tags
        s = s.replace(/<\/ul>\s*<ul>/g, "");
        // Paragraphs (double newline)
        s = s.replace(/\n\n+/g, "</p><p>");
        // Single newlines → <br>
        s = s.replace(/\n/g, "<br>");
        // Wrap
        s = "<p>" + s + "</p>";
        // Clean empty
        s = s.replace(/<p>\s*<\/p>/g, "");
        s = s.replace(/<p>\s*(<[huo])/g, "$1");
        s = s.replace(/(<\/[huo]l>)\s*<\/p>/g, "$1");
        return s;
    }

    // ---- Time formatter ----
    function timeStr() {
        const d = new Date();
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    // ---- Init ----
    createWidget();

    const toggle = document.getElementById("chatbot-toggle") || document.getElementById("cw-toggle");
    const win = document.getElementById("cw-window");
    const closeBtn = document.getElementById("cw-close");
    const messages = document.getElementById("cw-messages");
    const typing = document.getElementById("cw-typing");
    const textInput = document.getElementById("cw-text-input");
    const sendBtn = document.getElementById("cw-send-btn");
    const errorToast = document.getElementById("cw-error");
    const lightbox = document.getElementById("cw-lightbox");
    const lightboxImg = document.getElementById("cw-lightbox-img");
    const suggestions = document.getElementById("cw-suggestions");

    let isOpen = false;
    let isSending = false;

    // ---- Toggle open/close ----
    function openChat() {
        isOpen = true;
        toggle.classList.add("open");
        win.classList.remove("closing");
        win.classList.add("open");
        textInput.focus();
    }

    function closeChat() {
        isOpen = false;
        toggle.classList.remove("open");
        win.classList.remove("open");
        win.classList.add("closing");
        setTimeout(() => {
            win.classList.remove("closing");
        }, 300);
    }

    toggle.addEventListener("click", () => {
        if (isOpen) closeChat();
        else openChat();
    });

    closeBtn.addEventListener("click", closeChat);

    // ---- Close chatbot when tapping anywhere outside in the web UI ----
    document.addEventListener("click", (e) => {
        if (!isOpen) return;
        const isInsideWin = win && win.contains(e.target);
        const isInsideToggle = toggle && toggle.contains(e.target);
        const isInsideLightbox = lightbox && lightbox.contains(e.target);

        if (!isInsideWin && !isInsideToggle && !isInsideLightbox) {
            closeChat();
        }
    });

    // ---- Suggestion pills ----
    suggestions.addEventListener("click", (e) => {
        const btn = e.target.closest(".cw-suggestion");
        if (!btn) return;
        const msg = btn.dataset.msg;
        if (msg) {
            textInput.value = msg;
            sendMessage();
        }
    });

    // ---- Error toast ----
    function showError(msg) {
        errorToast.textContent = msg;
        errorToast.classList.add("active");
        setTimeout(() => errorToast.classList.remove("active"), 3000);
    }

    // ---- Lightbox ----
    lightbox.addEventListener("click", () => lightbox.classList.remove("active"));

    function openLightbox(src) {
        lightboxImg.src = src;
        lightbox.classList.add("active");
    }

    // ---- Add message to DOM ----
    // ---- Add message to DOM ----
    function addMessage(role, html, suggestionsArray = null) {
        const wrapper = document.createElement("div");
        wrapper.className = `cw-msg ${role}`;

        let inner = `<div class="cw-bubble">${html}</div>`;
        inner += `<span class="cw-time">${timeStr()}</span>`;

        if (role === "bot" && suggestionsArray && Array.isArray(suggestionsArray) && suggestionsArray.length > 0) {
            inner += `<div class="cw-suggestions-outside" style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; width: 100%; align-self: flex-start;">
                ${suggestionsArray.map(s => `<button type="button" class="cw-chip-btn" data-msg="${escapeHtml(s)}">${escapeHtml(s)}</button>`).join('')}
            </div>`;
        }

        wrapper.innerHTML = inner;
        // Insert before typing indicator
        messages.insertBefore(wrapper, typing);
        scrollBottom();
    }

    function scrollBottom() {
        requestAnimationFrame(() => {
            messages.scrollTop = messages.scrollHeight;
        });
    }

    // ---- Send message ----
    async function sendMessage() {
        if (isSending) return;

        const text = textInput.value.trim();
        if (!text) return;

        isSending = true;
        sendBtn.disabled = true;

        // Render user message
        addMessage("user", escapeHtml(text));

        // Remove welcome card after first message
        const welcome = messages.querySelector(".cw-welcome");
        if (welcome) welcome.remove();

        // Clear input
        textInput.value = "";

        // Show typing indicator
        typing.classList.add("active");
        scrollBottom();

        try {
            const resp = await fetch(API, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: text }),
            });

            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

            const data = await resp.json();
            typing.classList.remove("active");

            let botContent = "";

            if (data.confidence) {
                const badgeColor = data.confidence === 'high' ? '#22c55e' : (data.confidence === 'medium' ? '#f59e0b' : '#ef4444');
                const icon = data.confidence === 'high' ? '🟢' : (data.confidence === 'medium' ? '🟡' : '🔴');
                const hitsCount = data.hits_count !== undefined ? data.hits_count : (data.sources ? data.sources.length : 0);

                botContent += `<div style="display:flex; gap:8px; margin-bottom:8px; flex-wrap:wrap; align-items:center;">
                    <span style="background:${badgeColor}20; color:${badgeColor}; border:1px solid ${badgeColor}40; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600;">
                        ${icon} ${data.confidence.toUpperCase()} Confidence • ${hitsCount} sources
                    </span>
                    ${data.risk === 'high' ? `<span style="background:#ef444420; color:#ef4444; border:1px solid #ef444440; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600;">⚠️ Risk: High</span>` : ''}
                </div>`;
            }

            const rawReply = data.reply || data.response || data.answer || "I am PhishGuard AI Assistant. How can I help you analyze phishing threats?";
            botContent += md(rawReply);

            const suggestionsList = (data.suggestions && Array.isArray(data.suggestions)) ? data.suggestions : null;
            addMessage("bot", botContent, suggestionsList);
        } catch (err) {
            console.error("[ChatWidget] Error sending message:", err);
            typing.classList.remove("active");
            showError("Unable to reach Security Assistant. Please try again.");
            addMessage("bot", "⚠️ <em>Sorry, I encountered a temporary connection issue. Please check your internet connection or try again.</em>");
        } finally {
            isSending = false;
            sendBtn.disabled = false;
            textInput.focus();
        }
    }

    // ---- Handle click on dynamic chip suggestion buttons ----
    messages.addEventListener("click", (e) => {
        const btn = e.target.closest(".cw-chip-btn");
        if (!btn) return;
        const msg = btn.dataset.msg || btn.textContent.trim();
        if (msg) {
            textInput.value = msg;
            sendMessage();
        }
    });

    textInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    function escapeHtml(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }
})();
