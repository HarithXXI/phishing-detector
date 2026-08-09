// ==========================================================================
// PhishGuard AI — Premium Interactive Effects
// Glow risk ring · Hero text animation · Loading transitions
// ==========================================================================

(function () {
    "use strict";

    // Glow Ring on result hero card based on risk level
    window.applyHeroGlow = function applyHeroGlow() {
        const heroCard = document.getElementById("result-hero-card");
        if (!heroCard) return;

        heroCard.classList.remove("glow-high", "glow-med", "glow-low");
        const badge = document.querySelector(".risk-badge-text");
        if (!badge) return;

        const t = (badge.textContent || "").toUpperCase();
        if (t.includes("HIGH")) heroCard.classList.add("glow-high");
        else if (t.includes("MED")) heroCard.classList.add("glow-med");
        else heroCard.classList.add("glow-low");
    };

    // Typewriter hero heading
    document.addEventListener("DOMContentLoaded", () => {
        const heroH1 = document.querySelector(".hero h1");
        if (heroH1) {
            const orig = heroH1.textContent;
            heroH1.textContent = "";
            heroH1.style.opacity = "1";
            let i = 0;
            const type = () => {
                if (i < orig.length) {
                    heroH1.textContent += orig[i++];
                    setTimeout(type, 26);
                }
            };
            requestAnimationFrame(() => setTimeout(type, 200));
        }

        // Stagger entrance for loading steps
        document.querySelectorAll(".loading-step").forEach((el, i) => {
            el.style.opacity = "0";
            el.style.transform = "translateY(12px)";
            setTimeout(() => {
                el.style.transition = "opacity 400ms ease, transform 400ms ease";
                el.style.opacity = "1";
                el.style.transform = "";
            }, 100 + i * 80);
        });
    });
})();
