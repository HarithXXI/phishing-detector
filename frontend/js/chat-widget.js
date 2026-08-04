// ==========================================================================
// PhishGuard AI — Floating Chat Widget (Intercom Style)
// ==========================================================================

(function () {
    "use strict";

    const API = "http://localhost:8000/chat";
    const STREAM_API = "http://localhost:8000/chat/stream";
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
                    <div class="cw-welcome-sub">Ask me about phishing, suspicious links, email headers, or upload a screenshot for analysis.</div>
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
                <div class="cw-preview-row" id="cw-preview-row">
                    <img class="cw-preview-thumb" id="cw-preview-thumb" src="" alt="preview">
                    <span class="cw-preview-name" id="cw-preview-name"></span>
                    <button class="cw-preview-remove" id="cw-preview-remove" aria-label="Remove image">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="cw-input-row">
                    <button class="cw-img-btn" id="cw-img-btn" aria-label="Upload image">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                            <circle cx="8.5" cy="8.5" r="1.5"/>
                            <polyline points="21 15 16 10 5 21"/>
                        </svg>
                    </button>
                    <input type="file" accept="image/*" id="cw-file-input" hidden>
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
    const imgBtn = document.getElementById("cw-img-btn");
    const fileInput = document.getElementById("cw-file-input");
    const previewRow = document.getElementById("cw-preview-row");
    const previewThumb = document.getElementById("cw-preview-thumb");
    const previewName = document.getElementById("cw-preview-name");
    const previewRemove = document.getElementById("cw-preview-remove");
    const errorToast = document.getElementById("cw-error");
    const lightbox = document.getElementById("cw-lightbox");
    const lightboxImg = document.getElementById("cw-lightbox-img");
    const suggestions = document.getElementById("cw-suggestions");

    let isOpen = false;
    let isSending = false;
    let selectedFile = null;
    let selectedB64 = null;

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

    // ---- Image upload ----
    imgBtn.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", () => {
        const file = fileInput.files[0];
        if (!file) return;

        if (file.size > MAX_IMG_SIZE) {
            showError("Image must be under 5 MB");
            fileInput.value = "";
            return;
        }

        selectedFile = file;
        previewName.textContent = file.name;

        const reader = new FileReader();
        reader.onload = (e) => {
            selectedB64 = e.target.result;
            previewThumb.src = selectedB64;
            previewRow.classList.add("active");
        };
        reader.readAsDataURL(file);
    });

    previewRemove.addEventListener("click", clearImage);

    function clearImage() {
        selectedFile = null;
        selectedB64 = null;
        previewRow.classList.remove("active");
        previewThumb.src = "";
        previewName.textContent = "";
        fileInput.value = "";
    }

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
    function addMessage(role, html, imageDataUrl) {
        const wrapper = document.createElement("div");
        wrapper.className = `cw-msg ${role}`;

        let inner = "";

        if (imageDataUrl && role === "user") {
            inner += `<img class="cw-msg-image" src="${imageDataUrl}" alt="uploaded" onclick="document.getElementById('cw-lightbox-img').src=this.src; document.getElementById('cw-lightbox').classList.add('active');">`;
        }

        inner += `<div class="cw-bubble">${html}</div>`;
        inner += `<span class="cw-time">${timeStr()}</span>`;

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

    // ---- Render Knowledge Sources Pills ----
    function renderSources(sources) {
        if (!sources || !Array.isArray(sources) || sources.length === 0) return "";
        const uniqueSources = [...new Set(sources)];
        return `<div class="cw-sources">
            <div class="cw-sources-header">📚 <strong>Knowledge Sources:</strong></div>
            <div class="cw-sources-pills" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px;">
                ${uniqueSources.map(s => {
                    const srcPath = typeof s === "string" ? s : (s.path || s.rel_path || "");
                    const parts = srcPath.split("/");
                    const shortPath = parts.length >= 2 ? parts.slice(-2).join("/") : srcPath;
                    return `<span class="cw-source-pill" title="${escapeHtml(srcPath)}"><code>${escapeHtml(shortPath)}</code></span>`;
                }).join("")}
            </div>
        </div>`;
    }

    // ---- Render Knowledge Sources Pills ----
    function renderSources(sources) {
        if (!sources || !Array.isArray(sources) || sources.length === 0) return "";
        const uniqueSources = [...new Set(sources)];
        return `<div class="cw-sources">
            <div class="cw-sources-header">📚 <strong>Knowledge Sources:</strong></div>
            <div class="cw-sources-pills" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px;">
                ${uniqueSources.map(s => {
                    const srcPath = typeof s === "string" ? s : (s.path || s.rel_path || "");
                    const parts = srcPath.split("/");
                    const shortPath = parts.length >= 2 ? parts.slice(-2).join("/") : srcPath;
                    return `<span class="cw-source-pill" title="${escapeHtml(srcPath)}"><code>${escapeHtml(shortPath)}</code></span>`;
                }).join("")}
            </div>
        </div>`;
    }

    // ---- Send message ----
    async function sendMessage() {
        if (isSending) return;

        const text = textInput.value.trim();
        const hasImg = !!selectedFile;

        if (!text && !hasImg) return;

        isSending = true;
        sendBtn.disabled = true;

        // Render user message
        const userHtml = text ? escapeHtml(text) : (hasImg ? "<em>Image uploaded</em>" : "");
        addMessage("user", userHtml, hasImg ? selectedB64 : null);

        // Remove welcome card after first message
        const welcome = messages.querySelector(".cw-welcome");
        if (welcome) welcome.remove();

        // Clear input
        textInput.value = "";
        const imgToSend = selectedFile;
        clearImage();

        // Show typing
        typing.classList.add("active");
        scrollBottom();

        try {
            if (!imgToSend) {
                // --- STREAMING SSE MODE (ChatGPT Typing Effect) ---
                let streamSuccess = false;
                try {
                    const resp = await fetch(STREAM_API, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ message: text }),
                    });

                    if (resp.ok && resp.body) {
                        typing.classList.remove("active");

                        // Build bot message wrapper
                        const botWrapper = document.createElement("div");
                        botWrapper.className = "cw-msg bot";

                        const metaDiv = document.createElement("div");
                        metaDiv.className = "cw-meta-badges";

                        const bubbleDiv = document.createElement("div");
                        bubbleDiv.className = "cw-bubble";

                        const timeSpan = document.createElement("span");
                        timeSpan.className = "cw-time";
                        timeSpan.textContent = timeStr();

                        const suggestionsDiv = document.createElement("div");
                        suggestionsDiv.className = "cw-dynamic-suggestions";

                        botWrapper.appendChild(metaDiv);
                        botWrapper.appendChild(bubbleDiv);
                        botWrapper.appendChild(timeSpan);
                        botWrapper.appendChild(suggestionsDiv);

                        messages.insertBefore(botWrapper, typing);
                        scrollBottom();

                        const reader = resp.body.getReader();
                        const decoder = new TextDecoder();
                        let fullText = "";
                        let buffer = "";

                        while (true) {
                            const { done, value } = await reader.read();
                            if (done) break;
                            buffer += decoder.decode(value, { stream: true });
                            const lines = buffer.split("\n");
                            buffer = lines.pop() || ""; // Keep incomplete trailing chunk in buffer

                            for (const line of lines) {
                                const trimmed = line.trim();
                                if (trimmed.startsWith("data: ")) {
                                    try {
                                        const data = JSON.parse(trimmed.slice(6));
                                        if (data.type === "meta") {
                                            // Render Badges
                                            if (data.confidence) {
                                                const badgeColor = data.confidence === 'high' ? '#22c55e' : (data.confidence === 'medium' ? '#f59e0b' : '#ef4444');
                                                const icon = data.confidence === 'high' ? '🟢' : (data.confidence === 'medium' ? '🟡' : '🔴');
                                                const hitsCount = data.hits_count !== undefined ? data.hits_count : (data.sources ? data.sources.length : 0);

                                                metaDiv.innerHTML = `<div style="display:flex; gap:8px; margin-bottom:8px; flex-wrap:wrap; align-items:center;">
                                                    <span style="background:${badgeColor}20; color:${badgeColor}; border:1px solid ${badgeColor}40; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600;">
                                                        ${icon} ${data.confidence.toUpperCase()} Confidence • ${hitsCount} sources
                                                    </span>
                                                    ${data.risk === 'high' ? `<span style="background:#ef444420; color:#ef4444; border:1px solid #ef444440; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600;">⚠️ Risk: High - ${data.has_evilginx ? 'Evilginx/AiTM detected' : 'Phishing'}</span>` : ''}
                                                </div>`;
                                            }
                                        } else if (data.type === "token") {
                                            fullText += data.content;
                                            bubbleDiv.innerHTML = md(fullText);
                                            scrollBottom();
                                        } else if (data.type === "done") {
                                            if (data.suggestions && Array.isArray(data.suggestions) && data.suggestions.length > 0) {
                                                suggestionsDiv.innerHTML = `<div style="margin-top:12px; display:flex; flex-wrap:wrap; gap:6px;">
                                                    ${data.suggestions.map(s => `<button type="button" class="cw-chip-btn" data-msg="${escapeHtml(s)}" style="background:#1e293b; border:1px solid #334155; color:#94a3b8; padding:6px 12px; border-radius:20px; font-size:12px; cursor:pointer;">${escapeHtml(s)}</button>`).join('')}
                                                </div>`;
                                                scrollBottom();
                                            }
                                        }
                                    } catch (e) {
                                        continue;
                                    }
                                }
                            }
                        }
                        streamSuccess = true;
                    }
                } catch (e) {
                    streamSuccess = false;
                }

                if (streamSuccess) {
                    isSending = false;
                    sendBtn.disabled = false;
                    textInput.focus();
                    return;
                }
            }

            // Fallback non-streaming POST
            let fetchOptions;
            if (imgToSend) {
                const formData = new FormData();
                formData.append("message", text);
                formData.append("image", imgToSend);
                fetchOptions = { method: "POST", body: formData };
            } else {
                fetchOptions = {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ message: text }),
                };
            }

            const resp = await fetch(API, fetchOptions);
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
                    ${data.risk === 'high' ? `<span style="background:#ef444420; color:#ef4444; border:1px solid #ef444440; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600;">⚠️ Risk: High - ${data.has_evilginx ? 'Evilginx/AiTM detected' : 'Phishing'}</span>` : ''}
                </div>`;
            }

            botContent += md(data.reply);

            if (data.suggestions && Array.isArray(data.suggestions) && data.suggestions.length > 0) {
                botContent += `<div style="margin-top:12px; display:flex; flex-wrap:wrap; gap:6px;">
                    ${data.suggestions.map(s => `<button type="button" class="cw-chip-btn" data-msg="${escapeHtml(s)}" style="background:#1e293b; border:1px solid #334155; color:#94a3b8; padding:6px 12px; border-radius:20px; font-size:12px; cursor:pointer;">${escapeHtml(s)}</button>`).join('')}
                </div>`;
            }

            addMessage("bot", botContent);
        } catch (err) {
            typing.classList.remove("active");
            addMessage("bot", `<span style="color:#DC2626;">⚠️ Connection error: ${escapeHtml(err.message)}</span>`);
        }

        isSending = false;
        sendBtn.disabled = false;
        textInput.focus();
    }

    sendBtn.addEventListener("click", sendMessage);

    // Event delegation for dynamic suggestion chips
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
