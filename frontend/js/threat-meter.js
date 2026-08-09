/**
 * PhishGuard AI — Threat Meter - FIXED v2
 * No global variables, all null-checked
 */
window.setThreatScore = function setThreatScore(score) {
    try {
        score = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
        console.log('[ThreatMeter] setThreatScore', score);

        const scoreNumEl = document.getElementById('threat-score-num') || document.getElementById('scoreValue') || document.getElementById('score-number') || document.querySelector('.score-num');
        const meterFill = document.getElementById('threat-meter-fill') || document.getElementById('gaugeFill') || document.querySelector('.gauge-fill');
        const threatLabelEl = document.getElementById('threat-label') || document.getElementById('riskLabel');
        const maliciousBadge = document.getElementById("maliciousBadge");
        const riskGradient = document.getElementById("riskGradient");

        // 1. Animate half-arc
        if (meterFill) {
            const circumference = 251;
            const targetOffset = circumference - (score / 100) * circumference;
            meterFill.style.strokeDasharray = circumference;
            meterFill.style.strokeDashoffset = circumference;
            void meterFill.offsetWidth;
            meterFill.style.transition = "stroke-dashoffset 1.2s cubic-bezier(0.16, 1, 0.3, 1)";
            meterFill.style.strokeDashoffset = targetOffset;
        }

        // 2. Count up
        if (scoreNumEl) {
            const duration = 1200;
            const startTime = performance.now();
            function animateNumber(now) {
                const elapsed = now - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const ease = 1 - Math.pow(1 - progress, 3);
                const current = Math.floor(ease * score);
                scoreNumEl.textContent = current;
                if (progress < 1) requestAnimationFrame(animateNumber);
                else scoreNumEl.textContent = score;
            }
            requestAnimationFrame(animateNumber);
        }

        // 3. Tier colors
        if (score >= 75) {
            if (riskGradient) riskGradient.innerHTML = `<stop offset="0%" stop-color="#EF4444" /><stop offset="50%" stop-color="#F97316" /><stop offset="100%" stop-color="#F59E0B" />`;
            if (scoreNumEl) scoreNumEl.style.color = "#EF4444";
            if (threatLabelEl) { threatLabelEl.textContent = "High Risk"; threatLabelEl.style.color = "#DC2626"; }
            if (maliciousBadge) { maliciousBadge.className = "malicious-badge tier-high"; maliciousBadge.innerHTML = "<span>Malicious</span>"; }
        } else if (score >= 40) {
            if (riskGradient) riskGradient.innerHTML = `<stop offset="0%" stop-color="#F59E0B" /><stop offset="100%" stop-color="#EAB308" />`;
            if (scoreNumEl) scoreNumEl.style.color = "#F59E0B";
            if (threatLabelEl) { threatLabelEl.textContent = "Medium Risk"; threatLabelEl.style.color = "#D97706"; }
            if (maliciousBadge) { maliciousBadge.className = "malicious-badge tier-medium"; maliciousBadge.innerHTML = "<span>Suspicious</span>"; }
        } else {
            if (riskGradient) riskGradient.innerHTML = `<stop offset="0%" stop-color="#10B981" /><stop offset="100%" stop-color="#22C55E" />`;
            if (scoreNumEl) scoreNumEl.style.color = "#10B981";
            if (threatLabelEl) { threatLabelEl.textContent = "Low Risk"; threatLabelEl.style.color = "#10B981"; }
            if (maliciousBadge) { maliciousBadge.className = "malicious-badge tier-low"; maliciousBadge.innerHTML = "<span>Clean</span>"; }
        }
    } catch (err) {
        console.error('[ThreatMeter] Error in setThreatScore:', err);
    }
};
console.log('✓ ThreatMeter fixed v2 loaded');
