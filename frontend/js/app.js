// ==========================================================================
// PhishGuard AI — Premium Frontend Application
// ==========================================================================

const API_BASE = "http://localhost:8000";

// --- Example payloads ---
const EXAMPLES = {
    paypal: `Subject: Your PayPal account has been suspended!\n\nDear valued customer,\n\nWe have detected unauthorized access to your PayPal account. Your account has been temporarily suspended.\n\nYou must verify your identity within 24 hours or your account will be permanently closed.\n\nClick here to verify: http://192.168.1.1/paypal-verify/login\n\nPayPal Security Team`,

    email: `Subject: URGENT: Microsoft 365 Password Expiring Today!\n\nDear User,\n\nYour Microsoft 365 password will expire in 2 hours. Access to your email mailbox and corporate files will be restricted immediately.\n\nPlease confirm your current credentials and update your password now to avoid account termination:\n\nClick: http://m365-update-security.site/login\n\nIT Support Service Desk`,

    clean: `Hi Sarah,\n\nJust wanted to follow up on our meeting yesterday. I've attached the Q3 report as discussed.\n\nLet me know if you have any questions about the numbers. Happy to jump on a call this afternoon.\n\nBest,\nJohn`,

    sms: `FRM: Chase-Alert MSG: We detected suspicious login attempts from an unknown device in NY. Access has been restricted. Unlock your account immediately at http://chase-security-update.work/login. Fail to respond in 4 hours will close your account.`
};

// --- DOM References ---
const inputText = document.getElementById("input-text");
const btnAnalyze = document.getElementById("btn-analyze");
const loadingState = document.getElementById("loading-state");
const errorState = document.getElementById("error-state");
const errorMessage = document.getElementById("error-message");
const resultsSection = document.getElementById("results-section");

// --- Loading Step Refs ---
const stepRules = document.getElementById("step-rules");
const stepUrls = document.getElementById("step-urls");
const stepIntel = document.getElementById("step-intel");
const stepAi = document.getElementById("step-ai");

// --- Example Pills click handler ---
document.querySelectorAll(".btn-example-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
        const key = btn.dataset.example;
        if (EXAMPLES[key]) {
            inputText.value = EXAMPLES[key];
            inputText.focus();
        }
    });
});

// --- Trigger Analysis ---
btnAnalyze.addEventListener("click", (e) => {
    if (e) e.preventDefault();
    runAnalysis();
});

inputText.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runAnalysis();
    }
});

// --- Main Analysis Logic ---
async function runAnalysis() {
    const text = inputText.value.trim();
    if (!text) {
        showError("Please enter text");
        return;
    }

    // Reset states
    hideError();
    resultsSection.classList.remove("active");
    btnAnalyze.classList.add("loading");
    btnAnalyze.disabled = true;

    // Reset all loading steps
    resetLoadingSteps();
    loadingState.classList.add("active");

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s hard timeout

    const simulationPromise = startLoadingSimulation();
    let apiData = null;
    let apiError = null;

    try {
        console.log("[PhishGuard Frontend] Requesting API:", `${API_BASE}/api/analyze`, { text });
        const response = await fetch(`${API_BASE}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text }),
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`Server responded with HTTP ${response.status}`);
        }

        apiData = await response.json();
        console.log("[PhishGuard Frontend] API Response Received:", apiData);
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === "AbortError") {
            apiError = new Error("Analysis request timed out after 30 seconds");
            showToast("Analysis timed out after 30s. Please check backend connection.");
        } else {
            apiError = err;
        }
    } finally {
        // ALWAYS re-enable button after success or failure
        btnAnalyze.classList.remove("loading");
        btnAnalyze.disabled = false;
    }

    // Transition steps to completed
    if (apiData) {
        await finishLoadingSimulation();
        loadingState.classList.remove("active");
        renderResults(apiData);
    } else {
        loadingState.classList.remove("active");
        showError(apiError ? `${apiError.message}. Make sure your Python backend is running on port 8000.` : "An unexpected error occurred.");
    }
}

// --- Loading Step Helpers ---
function resetLoadingSteps() {
    [stepRules, stepUrls, stepIntel, stepAi].forEach(step => {
        step.className = "loading-step";
    });
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function startLoadingSimulation() {
    // 1. Rules
    stepRules.classList.add("active");
    await delay(350);
    stepRules.classList.remove("active");
    stepRules.classList.add("completed");

    // 2. URLs
    stepUrls.classList.add("active");
    await delay(350);
    stepUrls.classList.remove("active");
    stepUrls.classList.add("completed");

    // 3. Intel
    stepIntel.classList.add("active");
}

async function finishLoadingSimulation() {
    // Complete Intel
    stepIntel.classList.remove("active");
    stepIntel.classList.add("completed");

    // Start & complete AI reasoning
    stepAi.classList.add("active");
    await delay(300);
    stepAi.classList.remove("active");
    stepAi.classList.add("completed");
    await delay(150); // slight buffer before rendering
}

// --- Render Results ---
function renderResults(data) {
    if (resultsSection) {
        resultsSection.classList.add("active");
    }

    try {
        if (window.renderFraudTips) {
            const old = document.getElementById('pgFraudWrapper');
            if (old) old.remove();
            const wrapper = document.createElement('div');
            wrapper.id = 'pgFraudWrapper';
            const inputEl = document.getElementById('input-text');
            const textVal = inputEl ? inputEl.value : '';
            wrapper.innerHTML = window.renderFraudTips(textVal, data);
            resultsSection.appendChild(wrapper);
        }
    } catch (e) {
        console.error(e);
    }

    const score = data.score || 0;
    const riskLevel = (data.risk_level || "LOW").toUpperCase();
    
    // Theme Colors based on risk
    const theme = getRiskTheme(riskLevel);

    // Hero result card update
    const resultHeroCard = document.getElementById("result-hero-card");
    if (resultHeroCard) {
        resultHeroCard.style.backgroundColor = theme.bg;
        resultHeroCard.style.borderColor = theme.border;
    }

    // Score meter animation (if element exists)
    const scoreMeter = document.getElementById("score-meter");
    if (scoreMeter) {
        scoreMeter.style.stroke = theme.color;
        const circumference = 2 * Math.PI * 42; // r=42 -> 263.89
        const offset = circumference - (score / 100) * circumference;
        scoreMeter.style.strokeDasharray = circumference;
        scoreMeter.style.strokeDashoffset = circumference;
        scoreMeter.getBoundingClientRect();
        scoreMeter.style.strokeDashoffset = offset;
    }

    // Update half-arc threat meter gauge directly - SAFE WRAPPER
    try {
        if (typeof window.setThreatScore === "function") {
            window.setThreatScore(score);
        } else {
            countUpScore(score);
        }
    } catch(e) {
        console.error('setThreatScore failed, using fallback', e);
        countUpScore(score);
    }

    // Risk badge update
    const riskBadge = document.getElementById("risk-badge");
    if (riskBadge) {
        riskBadge.className = `risk-badge-premium`;
        riskBadge.style.color = theme.color;
        riskBadge.style.backgroundColor = theme.bgBadge;
        riskBadge.style.borderColor = theme.borderBadge;
        
        const badgeDot = riskBadge.querySelector(".risk-badge-dot");
        if (badgeDot) badgeDot.style.backgroundColor = theme.color;
        const badgeText = riskBadge.querySelector(".risk-badge-text");
        if (badgeText) badgeText.textContent = `${riskLevel} RISK`;
    }

    // Apply card glow effect safely
    if (typeof window.applyHeroGlow === "function") {
        window.applyHeroGlow();
    }

    // Attack Type & description
    const aiResult = data.ai_result || {};
    const attackTypeVal = document.getElementById("attack-type");
    const attackDesc = document.getElementById("attack-desc");
    const iconContainer = document.getElementById("attack-icon-container");

    const attackLabel = aiResult.attack_type || "none";
    if (attackTypeVal) attackTypeVal.textContent = formatAttackType(attackLabel);
    if (attackDesc) attackDesc.textContent = buildSummary(data);

    // Update attack icon
    if (iconContainer) {
        iconContainer.innerHTML = getAttackIcon(attackLabel, theme.color);
        iconContainer.style.backgroundColor = theme.bgBadge;
    }

    // --- Vector row counts & dots ---
    updateVectorRow("rule", data.risks || [], data.breakdown?.rule_engine || 0, 25);
    updateVectorRow("url", data.risks || [], data.breakdown?.url_heuristic || 0, 30);
    
    // Threat Intel details
    const threatFlow = data.detection_flow?.find(f => f.layer === "Threat Intelligence") || {};
    const vtResult = threatFlow.virustotal || {};
    const abResult = threatFlow.abuseipdb || {};

    updateThreatVectorRow("vt", vtResult.error ? 0 : vtResult.malicious || 0, data.breakdown?.virustotal || 0, 35, vtResult.error);
    updateThreatVectorRow("abuse", abResult.error ? 0 : abResult.abuseConfidenceScore || 0, data.breakdown?.abuseipdb || 0, 20, abResult.error);
    updateVectorRow("ai", aiResult.is_phishing ? [1] : [], (data.breakdown?.ai_reasoning || 0) + (data.breakdown?.ai_bonus || 0), 45);

    // --- Render subpanels ---
    renderRulePanel(data.risks || []);
    renderUrlPanel(data.risks || [], data.urls_found || []);
    renderVtPanel(vtResult, data.breakdown?.virustotal || 0);
    renderAbusePanel(abResult, data.breakdown?.abuseipdb || 0);
    renderAiPanel(aiResult, data.breakdown?.ai_reasoning || 0, data.breakdown?.ai_bonus || 0);

    // --- Timeline ---
    renderTimeline(data.detection_flow || []);

    // Show section
    resultsSection.classList.add("active");
    
    // Close all open panels initially
    document.querySelectorAll(".row-detail-panel").forEach(panel => {
        panel.classList.remove("open");
        panel.style.maxHeight = "0px";
        panel.previousElementSibling.classList.remove("open");
    });

    // Auto-open first panel if active rule hits exist
    const rulesPanel = document.getElementById("rule-details");
    if (rulesPanel && rulesPanel.querySelector("li:not(.clean-item)")) {
        toggleDetailCard("rule-details");
    }

    // Auto smooth scroll down to results section cleanly
    scrollToResults();
}

function scrollToResults() {
    setTimeout(() => {
        const target = document.querySelector(".threat-score-card") || resultsSection;
        if (!target) return;
        const rect = target.getBoundingClientRect();
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const targetY = rect.top + scrollTop - 24;

        window.scrollTo({
            top: Math.max(0, targetY),
            behavior: "smooth"
        });
    }, 150);
}

// --- Score Number Count-up ---
function countUpScore(target) {
    const el = document.getElementById("scoreValue") || document.getElementById("score-number");
    if (!el) return;
    const duration = 800;
    const start = 0;
    const end = target;
    const startTime = performance.now();

    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // easeOutQuad
        const ease = progress * (2 - progress);
        const current = Math.floor(ease * (end - start) + start);
        el.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            el.textContent = end;
        }
    }
    requestAnimationFrame(update);
}

// --- Vector Row Helpers ---
function updateVectorRow(type, riskList, score, maxScore) {
    if (type === "ai") {
        const isPhish = score > 0;
        document.getElementById(`row-ai-count`).textContent = isPhish ? `Flagged · ${score}/${maxScore}` : `Clean · 0/${maxScore}`;
        const dot = document.getElementById(`row-ai-dot`);
        dot.style.backgroundColor = isPhish ? getSeverityColor(score / maxScore) : "var(--border-color)";
        return;
    }

    const isUrl = type === "url";
    const filteredRisks = (riskList || []).filter(r => {
        if (typeof r !== "string") return false;
        const isUrlPattern = isUrlRisk(r);
        return isUrl ? isUrlPattern : !isUrlPattern;
    });

    const countLabel = isUrl 
        ? `${filteredRisks.length} flag${filteredRisks.length !== 1 ? "s" : ""}`
        : `${filteredRisks.length} match${filteredRisks.length !== 1 ? "es" : ""}`;

    document.getElementById(`row-${type}-count`).textContent = `${countLabel} · ${score}/${maxScore}`;
    
    // Status dot
    const dot = document.getElementById(`row-${type}-dot`);
    dot.style.backgroundColor = score > 0 ? getSeverityColor(score / maxScore) : "var(--border-color)";
}

function updateThreatVectorRow(type, rawScore, contribution, maxScore, error) {
    const countEl = document.getElementById(`row-${type}-count`);
    const dot = document.getElementById(`row-${type}-dot`);

    if (error) {
        countEl.textContent = "skipped";
        dot.style.backgroundColor = "var(--border-color)";
        return;
    }

    if (type === "vt") {
        countEl.textContent = rawScore > 0 ? `${rawScore} alert${rawScore !== 1 ? "s" : ""} · ${contribution}/${maxScore}` : `0 alerts · 0/${maxScore}`;
    } else {
        countEl.textContent = `${rawScore}% confidence · ${contribution}/${maxScore}`;
    }

    dot.style.backgroundColor = contribution > 0 ? getSeverityColor(contribution / maxScore) : "var(--border-color)";
}

// --- Subpanel Rendering ---
function renderRulePanel(risks) {
    const list = document.getElementById("rule-list");
    const ruleRisks = risks.filter(r => !isUrlRisk(r));

    if (ruleRisks.length === 0) {
        list.innerHTML = `<li class="clean-item">No rule matching signature hits identified.</li>`;
    } else {
        list.innerHTML = ruleRisks.map((r, i) => 
            `<li style="animation-delay: ${i * 60}ms">${escapeHtml(r)}</li>`
        ).join("");
    }
}

function renderUrlPanel(risks, urls) {
    const list = document.getElementById("url-list");
    const urlRisks = risks.filter(r => isUrlRisk(r));
    let html = "";

    if (urls.length > 0) {
        html += urls.map((u, i) => 
            `<li class="clean-item" style="word-break: break-all; animation-delay: ${i * 60}ms"><code style="font-family: var(--font-mono); font-size: 12px;">${escapeHtml(u)}</code></li>`
        ).join("");
    }

    if (urlRisks.length > 0) {
        html += urlRisks.map((r, i) => 
            `<li style="animation-delay: ${(urls.length + i) * 60}ms">${escapeHtml(r)}</li>`
        ).join("");
    }

    if (!html) {
        html = `<li class="clean-item">No URLs extracted or analyzed.</li>`;
    }
    list.innerHTML = html;
}

function renderVtPanel(vt, score) {
    const body = document.getElementById("vt-body");
    if (vt.error) {
        body.innerHTML = `
            <div class="data-row">
                <span class="data-label">Status</span>
                <span class="data-value error-text">${escapeHtml(vt.error)}</span>
            </div>`;
        return;
    }

    body.innerHTML = `
        <div class="data-row" style="animation-delay: 50ms">
            <span class="data-label">Malicious Flagged Vendors</span>
            <span class="data-value" style="color: ${vt.malicious > 0 ? "var(--high-color)" : "inherit"}">${vt.malicious || 0}</span>
        </div>
        <div class="data-row" style="animation-delay: 110ms">
            <span class="data-label">Suspicious Flagged Vendors</span>
            <span class="data-value" style="color: ${vt.suspicious > 0 ? "var(--med-color)" : "inherit"}">${vt.suspicious || 0}</span>
        </div>
        <div class="data-row" style="animation-delay: 170ms">
            <span class="data-label">Score Contribution</span>
            <span class="data-value">${score}pts</span>
        </div>
    `;
}

function renderAbusePanel(abuse, score) {
    const body = document.getElementById("abuse-body");
    if (abuse.error) {
        body.innerHTML = `
            <div class="data-row">
                <span class="data-label">Status</span>
                <span class="data-value error-text">${escapeHtml(abuse.error)}</span>
            </div>`;
        return;
    }

    const conf = abuse.abuseConfidenceScore || 0;
    body.innerHTML = `
        <div class="data-row" style="animation-delay: 50ms">
            <span class="data-label">Abuse Confidence Score</span>
            <span class="data-value" style="color: ${conf > 50 ? "var(--med-color)" : "inherit"}">${conf}%</span>
        </div>
        <div class="data-row" style="animation-delay: 110ms">
            <span class="data-label">Total Logs Reported (90d)</span>
            <span class="data-value">${abuse.totalReports || 0}</span>
        </div>
        <div class="data-row" style="animation-delay: 170ms">
            <span class="data-label">Score Contribution</span>
            <span class="data-value">${score}pts</span>
        </div>
    `;
}

function renderAiPanel(ai, score, bonus) {
    const body = document.getElementById("ai-body");
    if (ai.error) {
        body.innerHTML = `
            <div class="data-row">
                <span class="data-label">Status</span>
                <span class="data-value error-text">${escapeHtml(ai.error)}</span>
            </div>`;
        return;
    }

    let html = `
        <div class="data-row" style="animation-delay: 50ms">
            <span class="data-label">Verdict Verdict</span>
            <span class="data-value">${ai.is_phishing ? "🚨 Potential Threat" : "🟢 Clean / Legitimate"}</span>
        </div>
        <div class="data-row" style="animation-delay: 100ms">
            <span class="data-label">Gemini Risk Level</span>
            <span class="data-value">${ai.risk_level || "LOW"}</span>
        </div>
        <div class="data-row" style="animation-delay: 150ms">
            <span class="data-label">Social Engineering Detected</span>
            <span class="data-value">${ai.social_engineering_detected ? "Yes" : "No"}</span>
        </div>
        <div class="data-row" style="animation-delay: 200ms">
            <span class="data-label">Total Layer Contribution</span>
            <span class="data-value">${score + bonus}pts</span>
        </div>
    `;

    const reasons = ai.reasons || [];
    if (reasons.length > 0) {
        html += `<ul class="ai-reasons-list">`;
        html += reasons.map((r, i) => `<li style="animation-delay: ${(5 + i) * 50}ms">${escapeHtml(r)}</li>`).join("");
        html += `</ul>`;
    }

    body.innerHTML = html;
}

// --- Timeline flow ---
function renderTimeline(flow) {
    const timeline = document.getElementById("flow-timeline");
    if (!flow || flow.length === 0) {
        timeline.innerHTML = `<div class="timeline-step"><span class="timeline-name">No steps run.</span></div>`;
        return;
    }

    timeline.innerHTML = flow.map((step) => {
        const isErr = step.error || step.virustotal?.error || step.abuseipdb?.error;
        let compClass = "timeline-step completed";
        if (isErr) compClass = "timeline-step has-error";

        let detail = "";
        if (step.layer === "Rule-Based Engine") {
            detail = `${step.findings || 0} signature match${step.findings !== 1 ? "es" : ""}`;
        } else if (step.layer === "URL Heuristic Engine") {
            detail = `${step.findings || 0} flag${step.findings !== 1 ? "s" : ""} on ${step.urls_found || 0} link${step.urls_found !== 1 ? "s" : ""}`;
        } else if (step.layer === "Threat Intelligence") {
            if (step.virustotal?.error && step.abuseipdb?.error) {
                detail = "threat intelligence services offline";
            } else {
                detail = `VT: ${step.virustotal?.malicious || 0} mal · AbuseIPDB: ${step.abuseipdb?.abuseConfidenceScore || 0}%`;
            }
        } else if (step.layer === "AI Reasoning (Gemini)") {
            detail = step.error ? "Gemini agent call skipped" : `classification: ${step.attack_type || "none"}`;
        }

        return `
            <div class="${compClass}">
                <div class="timeline-dot"></div>
                <span class="timeline-name">${escapeHtml(step.layer)}</span>
                <span class="timeline-detail">${escapeHtml(detail)}</span>
            </div>
        `;
    }).join("");
}

// --- Detail Card Accordion Handler ---
function toggleDetailCard(id) {
    const panel = document.getElementById(id);
    const row = panel.previousElementSibling;
    
    const isOpen = panel.classList.contains("open");

    // Close all panels
    document.querySelectorAll(".row-detail-panel").forEach(p => {
        p.classList.remove("open");
        p.style.maxHeight = "0px";
        p.previousElementSibling.classList.remove("open");
    });

    // If it wasn't open, open it
    if (!isOpen) {
        panel.classList.add("open");
        panel.style.maxHeight = panel.scrollHeight + "px";
        row.classList.add("open");
    }
}

// --- Visual Style Mapping Helpers ---
function getRiskTheme(level) {
    if (level === "HIGH") {
        return {
            color: "var(--high-color)",
            bg: "var(--high-bg)",
            border: "var(--high-border)",
            bgBadge: "var(--high-badge-bg)",
            borderBadge: "var(--high-badge-border)"
        };
    } else if (level === "MEDIUM") {
        return {
            color: "var(--med-color)",
            bg: "var(--med-bg)",
            border: "var(--med-border)",
            bgBadge: "var(--med-badge-bg)",
            borderBadge: "var(--med-badge-border)"
        };
    } else {
        return {
            color: "var(--low-color)",
            bg: "var(--low-bg)",
            border: "var(--low-border)",
            bgBadge: "var(--low-badge-bg)",
            borderBadge: "var(--low-badge-border)"
        };
    }
}

function getSeverityColor(ratio) {
    if (ratio >= 0.7) return "var(--high-color)";
    if (ratio >= 0.4) return "var(--med-color)";
    return "var(--low-color)";
}

function getAttackIcon(attack, color) {
    // Shield alert or clean shield
    if (!attack || attack === "none" || attack === "unknown") {
        return `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
    }
    // Threat alert triangle
    return `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
}

function isUrlRisk(riskString) {
    if (typeof riskString !== "string") return false;
    return riskString.includes("IP address") || riskString.includes("subdomain") || riskString.includes("URL") || 
           riskString.includes("HTTP (no TLS)") || riskString.includes("Punycode") || riskString.includes("hyphens") || 
           riskString.includes("TLD") || riskString.includes("Brand spoofing") || riskString.includes("long URL") || 
           riskString.includes("Typosquatting") || riskString.includes("Malformed");
}

function formatAttackType(type) {
    if (!type || type === "none" || type === "unknown") return "Clean / None Detected";
    return type
        .replace(/_/g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase());
}

function buildSummary(data) {
    const risks = data.risks || [];
    const vt = data.detection_flow?.find(f => f.layer === "Threat Intelligence")?.virustotal || {};
    const abuse = data.detection_flow?.find(f => f.layer === "Threat Intelligence")?.abuseipdb || {};
    const ai = data.ai_result || {};

    const points = [];
    if (risks.filter(r => !isUrlRisk(r)).length > 0) points.push("suspicious messaging triggers");
    if (risks.filter(r => isUrlRisk(r)).length > 0) points.push("anomalous link structures");
    if (vt.malicious > 0) points.push("known blacklisted threats");
    if (abuse.abuseConfidenceScore > 50) points.push("reported IP abuse historical data");
    if (ai.is_phishing) points.push("AI semantic phishing detection");

    if (points.length === 0) return "All validation layers completed successfully with no active threats identified.";
    return "Identified Indicators: " + points.join(", ") + ". Check specific threat categories below for logs.";
}

function showError(msg) {
    errorMessage.textContent = msg;
    errorState.classList.add("active");
    errorState.scrollIntoView({ behavior: "smooth", block: "start" });
}

function hideError() {
    errorState.classList.remove("active");
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

// --- Boot check ---
(async function () {
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        if (data.status === "ok") {
            console.log("✓ Live Engine API Active");
        }
    } catch {
        console.warn("✗ PhishGuard API is offline.");
    }
})();

// --- Theme Toggle Logic ---
const themeToggle = document.getElementById("theme-toggle");

// Load stored theme or default to light
if (localStorage.getItem("theme") === "dark") {
    document.body.classList.add("dark-mode");
}

themeToggle.addEventListener("click", () => {
    // Add clicked class for rotation animation
    themeToggle.classList.add("clicked");
    setTimeout(() => themeToggle.classList.remove("clicked"), 400);

    // Toggle dark mode class
    const isDark = document.body.classList.toggle("dark-mode");
    localStorage.setItem("theme", isDark ? "dark" : "light");
});

// --- Hidable Left Sidebar & Fraud Panel Accordion Logic ---
const appSidebar = document.getElementById("appSidebar");
const sidebarOpen = document.getElementById("sidebarOpen");
const sidebarClose = document.getElementById("sidebarClose");
const sidebarBackdrop = document.getElementById("sidebarBackdrop");

const reportToggle = document.getElementById("reportToggle");
const fraudPanel = document.getElementById("fraudPanel");

function openAppSidebar() {
    if (appSidebar && sidebarBackdrop) {
        appSidebar.classList.add("open");
        sidebarBackdrop.classList.add("active");
        if (window.innerWidth <= 900) {
            document.body.style.overflow = "hidden";
        }
    }
}

function closeAppSidebar() {
    if (appSidebar && sidebarBackdrop) {
        appSidebar.classList.remove("open");
        sidebarBackdrop.classList.remove("active");
        document.body.style.overflow = "";
    }
}

if (sidebarOpen) {
    sidebarOpen.addEventListener("click", () => {
        if (appSidebar.classList.contains("open")) {
            closeAppSidebar();
        } else {
            openAppSidebar();
        }
    });
}

if (sidebarClose) {
    sidebarClose.addEventListener("click", closeAppSidebar);
}

if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeAppSidebar);
}

if (reportToggle && fraudPanel) {
    reportToggle.addEventListener("click", () => {
        const isOpen = fraudPanel.classList.toggle("open");
        reportToggle.classList.toggle("active", isOpen);
        reportToggle.setAttribute("aria-expanded", isOpen);
    });
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && appSidebar && appSidebar.classList.contains("open")) {
        closeAppSidebar();
    }
});

// Map each fraud category to official portal
const fraudLinks = {
    email: "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx",
    sms: "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx",
    phone: "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx",
    website: "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx",
    social: "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx",
    other: "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx"
};

function showToast(message) {
    const existing = document.querySelector(".toast-notification");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = "toast-notification";
    toast.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        <span>${message}</span>
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.3s ease";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Handle clicking on any fraud card inside sidebar
document.querySelectorAll(".fraud-card").forEach((card) => {
    card.addEventListener("click", () => {
        const type = (card.dataset.type || "other").toLowerCase();
        const targetUrl = fraudLinks[type] || "https://cybercrime.gov.in";

        closeAppSidebar();
        showToast("Redirecting to National Cyber Crime Reporting Portal - cybercrime.gov.in");
        window.open(targetUrl, "_blank", "noopener,noreferrer");
    });
});

// --- Separate Sandboxed URL Preview Handlers ---
const inputLinkSep = document.getElementById("input-link-separate");
const btnPreviewUrl = document.getElementById("btn-preview-url");
const btnClearUrl = document.getElementById("btn-clear-url");
const dummyContainer = document.getElementById("dummy-browser-container");

if (btnPreviewUrl && inputLinkSep && dummyContainer) {
    btnPreviewUrl.addEventListener("click", async () => {
        const urlVal = (inputLinkSep.value || "").trim();
        if (!urlVal) {
            showToast("Please paste a URL first to preview");
            inputLinkSep.focus();
            return;
        }

        dummyContainer.classList.remove("empty");
        dummyContainer.innerHTML = `<div class="empty-state" style="padding:40px; text-align:center; display:flex; flex-direction:column; align-items:center; gap:12px;">
            <div class="btn-spinner" style="display:block; border-top-color:#2563EB; width:24px; height:24px;"></div>
            <div>🌐 Contacting isolated cloud browser for <strong>${urlVal}</strong>...</div>
        </div>`;

        try {
            const [analyzeRes, previewRes] = await Promise.all([
                fetch(`${API_BASE}/api/analyze`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ text: urlVal }),
                }).then(r => r.ok ? r.json() : {}).catch(() => ({})),
                fetch(`${API_BASE}/api/preview?url=${encodeURIComponent(urlVal)}`)
                    .then(r => r.ok ? r.json() : {})
                    .catch(() => ({ final_url: urlVal, screenshot_url: `https://api.microlink.io/?url=${encodeURIComponent(urlVal)}&screenshot=true&meta=false&embed=screenshot.url` }))
            ]);

            const mergedData = { ...analyzeRes, ...previewRes };
            if (window.renderDummyBrowser) {
                dummyContainer.innerHTML = window.renderDummyBrowser(mergedData, urlVal);
            }
        } catch (err) {
            if (window.renderDummyBrowser) {
                dummyContainer.innerHTML = window.renderDummyBrowser({ final_url: urlVal }, urlVal);
            }
        }
    });
}

if (btnClearUrl && inputLinkSep && dummyContainer) {
    btnClearUrl.addEventListener("click", () => {
        inputLinkSep.value = "";
        dummyContainer.classList.add("empty");
        dummyContainer.innerHTML = `<div class="empty-state">Paste a URL above and click Preview to see safe screenshot</div>`;
    });
}



