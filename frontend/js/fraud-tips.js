/**
 * PhishGuard AI — Fraud Tips & Risk Disclaimer Engine
 */

(function () {
    "use strict";

    function iconSVG(name) {
        switch (name) {
            case "lock":
                return `<svg viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    <circle cx="12" cy="16" r="1"/>
                </svg>`;
            case "link":
                return `<svg viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                </svg>`;
            case "user":
                return `<svg viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                    <circle cx="12" cy="7" r="4"/>
                </svg>`;
            case "shield":
                return `<svg viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>`;
            case "phone":
                return `<svg viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>
                </svg>`;
            default:
                return `<svg viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>`;
        }
    }

    function extractDomain(urlStr) {
        if (!urlStr) return "unknown link";
        try {
            const formatted = urlStr.startsWith("http") ? urlStr : "https://" + urlStr;
            const parsed = new URL(formatted);
            return parsed.hostname || urlStr;
        } catch (e) {
            return urlStr;
        }
    }

    function getFraudData(inputText, apiData) {
        const text = (inputText || "").toLowerCase();
        const score = apiData.score !== undefined ? apiData.score : (apiData.composite_score || 0);
        const riskLevel = (apiData.risk_level || apiData.threat_level || "LOW").toUpperCase();
        const attackType = (apiData.attack_type || (apiData.ai_result && apiData.ai_result.attack_type) || "").toLowerCase();
        const urls = apiData.urls_found || [];
        const domain = urls.length > 0 ? extractDomain(urls[0]) : "unknown link";

        // Detect type
        let type = "generic";
        if (text.includes("paypal") || attackType.includes("paypal") || domain.includes("paypal")) {
            type = "paypal";
        } else if (
            text.includes("chase") || text.includes("sbi") || text.includes("hdfc") ||
            text.includes("icici") || text.includes("bank") || text.includes("credential") ||
            attackType.includes("bank") || attackType.includes("credential")
        ) {
            type = "bank";
        } else if (
            text.includes("delivery") || text.includes("bluedart") || text.includes("fedex") ||
            text.includes("dhl") || text.includes("tracking") || text.includes("parcel") || text.includes("package")
        ) {
            type = "delivery";
        } else if (
            text.includes("crypto") || text.includes("wallet") || text.includes("binance") || text.includes("bitcoin")
        ) {
            type = "crypto";
        } else if (text.includes("sms") || attackType.includes("sms") || attackType.includes("smishing")) {
            type = "sms";
        }

        // Detect inputType
        let inputType = "Link";
        if (text.includes("@") && text.includes("subject:")) {
            inputType = "Email";
        } else if ((text.includes("frm:") || text.includes("sms") || text.length < 300) && !text.startsWith("http")) {
            inputType = "SMS";
        }

        return { text, score, riskLevel, attackType, urls, domain, type, inputType, apiData };
    }

    function buildDisclaimer(fraud) {
        const { type, inputType, riskLevel, domain, score } = fraud;

        if (type === "paypal") {
            if (riskLevel === "HIGH") {
                return `This ${inputType} impersonates PayPal. Detected domain (${domain}) is not official PayPal (official is paypal.com). PayPal never suspends accounts via link.`;
            } else if (riskLevel === "MEDIUM") {
                return `This ${inputType} mentions PayPal. Exercise caution with domain ${domain} and verify sender email before clicking.`;
            } else {
                return `This message mentions PayPal. Always double-check that URLs lead strictly to official paypal.com.`;
            }
        }

        if (type === "bank") {
            if (riskLevel === "HIGH") {
                return `This ${inputType} claims your bank account will be blocked. Banks never send block links via ${inputType}. Detected: ${domain}`;
            } else if (riskLevel === "MEDIUM") {
                return `This ${inputType} references banking services. Verify sender authenticity with your bank before clicking links (${domain}).`;
            } else {
                return `This banking message appears normal. Always use your official mobile banking app to log in.`;
            }
        }

        if (type === "delivery") {
            if (riskLevel === "HIGH") {
                return `This tracking link (${domain}) is not from official courier services. Never pay delivery fees via unknown links.`;
            } else if (riskLevel === "MEDIUM") {
                return `This delivery message contains link ${domain}. Verify shipment tracking on official courier portal.`;
            } else {
                return `This delivery update appears standard. Cross-reference tracking code on official courier portal.`;
            }
        }

        // Generic / Crypto / SMS
        if (riskLevel === "HIGH") {
            return `This ${inputType} has been flagged as HIGH RISK (${score}%). Do not click links, download attachments, or share sensitive information.`;
        } else if (riskLevel === "MEDIUM") {
            return `This ${inputType} shows suspicious patterns (${score}% Risk). Verify the domain (${domain}) carefully before proceeding.`;
        } else {
            return `This ${inputType} appears to have low risk factors (${score}%). Remain vigilant when sharing personal credentials.`;
        }
    }

    function buildTips(fraud) {
        const { type } = fraud;

        if (type === "paypal") {
            return [
                { icon: "lock", text: "Never share OTP, PIN, or PayPal password with anyone." },
                { icon: "link", text: "Don't click PayPal links from email — open paypal.com manually in your browser." },
                { icon: "user", text: "Verify sender: real PayPal emails come from @paypal.com, not @paypal-secure.com." },
                { icon: "shield", text: "Report phishing emails to spoof@paypal.com immediately." },
                { icon: "phone", text: "Use official PayPal website and mobile app only." },
                { icon: "lock", text: "Enable Two-Factor Authentication (2FA) on your PayPal account." },
                { icon: "link", text: "Check typos in URLs (e.g. paypaI.com vs paypal.com)." },
                { icon: "shield", text: "PayPal will never ask for your full password or card PIN via email." }
            ];
        }

        if (type === "bank") {
            return [
                { icon: "lock", text: "Never share OTP, ATM PIN, or Internet Banking credentials." },
                { icon: "link", text: "Don't click bank links from SMS — use your official banking app." },
                { icon: "user", text: "Verify sender ID: legitimate banks use official short codes." },
                { icon: "phone", text: "Report financial cyber frauds to 1930 Cyber Helpline immediately." },
                { icon: "shield", text: "Use official bank website and mobile application only." },
                { icon: "lock", text: "If money is debited unauthorizedly, call 1930 within 2 hours (Golden Hour)." },
                { icon: "link", text: "Banks never ask for full Card Number + CVV + OTP together." },
                { icon: "user", text: "Call official customer support number printed on the back of your debit card." }
            ];
        }

        if (type === "delivery") {
            return [
                { icon: "lock", text: "Never share OTP for package delivery unless courier boy is at your doorstep." },
                { icon: "link", text: "Don't click tracking links from unknown numbers — check official courier website." },
                { icon: "user", text: "Verify tracking number directly on the official courier portal." },
                { icon: "shield", text: "Report suspicious delivery messages to the courier support." },
                { icon: "phone", text: "Use official courier website or mobile app only." },
                { icon: "lock", text: "India Post / BlueDart never ask for address update fee payment via SMS link." },
                { icon: "link", text: "Check AWB tracking code on official courier portal." },
                { icon: "user", text: "Delivery OTP is meant for delivery executive confirmation only." }
            ];
        }

        // Generic
        return [
            { icon: "lock", text: "Never share OTP, passwords, or personal identification details." },
            { icon: "link", text: "Don't click on links from unknown or unverified sources." },
            { icon: "user", text: "Verify sender identity before responding or taking action." },
            { icon: "shield", text: "Report suspicious activity and phishing messages immediately." },
            { icon: "phone", text: "Use official websites and verified applications only." },
            { icon: "link", text: "Hover over links before clicking to reveal true destination URL." },
            { icon: "lock", text: "Urgency + Threat of loss = Signature red flag of phishing scam." },
            { icon: "shield", text: "When in doubt, contact official customer support directly." }
        ];
    }

    function renderFraudSection(inputText, apiData) {
        if (!apiData) return "";

        const fraud = getFraudData(inputText, apiData);
        const { type, inputType, riskLevel, score, apiData: data } = fraud;

        // Class for risk level
        const riskClass = riskLevel.toLowerCase();

        // Header Title
        let headerTitle = "";
        if (riskLevel === "HIGH") {
            headerTitle = `⚠️ DO NOT INTERACT - ${type.toUpperCase()} - ${score}% Risk`;
        } else if (riskLevel === "MEDIUM") {
            headerTitle = `⚡ VERIFY BEFORE CLICKING - ${type.toUpperCase()} - ${score}% Risk`;
        } else {
            headerTitle = `✅ LOOKS SAFE - ${type.toUpperCase()} - ${score}% Risk`;
        }

        // Disclaimer text
        const disclaimerText = buildDisclaimer(fraud);

        // Reason Pills
        const risks = data.risks || [];
        const aiReasons = (data.ai_result && data.ai_result.reasons) || [];
        const combinedReasons = [...risks.slice(0, 4), ...aiReasons.slice(0, 2)];

        let pillsHTML = "";
        if (combinedReasons.length > 0) {
            pillsHTML = `<div class="pg-disclaimer-pills">
                ${combinedReasons.map(r => `<span class="pg-reason-pill">${escapeHTML(r)}</span>`).join("")}
            </div>`;
        }

        // Tips
        const tips = buildTips(fraud);
        const first5 = tips.slice(0, 5);
        const remaining = tips.slice(5);

        const first5HTML = first5.map(t => `<div class="pg-tip-row">
            <div class="pg-tip-icon">${iconSVG(t.icon)}</div>
            <div class="pg-tip-text">${escapeHTML(t.text)}</div>
        </div>`).join("");

        const remainingHTML = remaining.map(t => `<div class="pg-tip-row">
            <div class="pg-tip-icon">${iconSVG(t.icon)}</div>
            <div class="pg-tip-text">${escapeHTML(t.text)}</div>
        </div>`).join("");

        const typeFormatted = type.charAt(0).toUpperCase() + type.slice(1);

        const html = `
        <div id="pgFraudContainer">
            <!-- Disclaimer Card -->
            <div class="pg-disclaimer-card ${riskClass}">
                <div class="pg-disclaimer-header">
                    <div class="pg-disclaimer-title">${headerTitle}</div>
                </div>
                <div class="pg-disclaimer-text">${disclaimerText}</div>
                ${pillsHTML}
                <div class="pg-disclaimer-note">* Analysis generated by PhishGuard AI multi-layer heuristic & AI reasoning engine.</div>
            </div>

            <!-- Fraud Prevention Tips Card -->
            <div class="pg-tips-card">
                <div class="pg-tips-title">Fraud Prevention Tips - ${typeFormatted} ${inputType}</div>
                <div class="pg-tips-list">
                    ${first5HTML}
                    <div id="pgExtraTips">
                        ${remainingHTML}
                    </div>
                </div>
                <button type="button" class="pg-tips-btn" id="pgToggleTipsBtn">
                    View All Tips
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </button>
            </div>
        </div>`;

        // Attach event listener after injection via microtask
        setTimeout(() => {
            const btn = document.getElementById("pgToggleTipsBtn");
            const extra = document.getElementById("pgExtraTips");
            if (btn && extra) {
                btn.addEventListener("click", function () {
                    const isOpen = extra.classList.toggle("open");
                    btn.innerHTML = isOpen
                        ? `Show Less <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>`
                        : `View All Tips <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>`;
                });
            }
        }, 50);

        return html;
    }

    function escapeHTML(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Expose to window
    window.renderFraudTips = renderFraudSection;
})();
