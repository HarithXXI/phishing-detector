"""
Rule-Based Phishing Detection Engine
Scans email/message text for phishing indicators using deterministic pattern matching.
"""

import re

PHISHING_PATTERNS = [
    (re.compile(r"\burgent\b", re.IGNORECASE),
     "Urgency language detected: 'urgent'"),

    (re.compile(r"\bverify\s+(your\s+)?(account|identity|information|email)\b", re.IGNORECASE),
     "Verification request detected (credential harvesting pattern)"),

    (re.compile(r"\b(log\s*in|sign\s*in|click\s+here\s+to\s+login)\b", re.IGNORECASE),
     "Login prompt detected in message body"),

    (re.compile(r"\bpassword\b", re.IGNORECASE),
     "Password reference detected"),

    (re.compile(r"\baccount\s+(has\s+been\s+)?(suspended|locked|disabled|closed|compromised|credited)\b", re.IGNORECASE),
     "Account status / financial credit notice detected"),

    (re.compile(r"\b(payment|transaction)\s+(failed|declined|unauthorized)\b", re.IGNORECASE),
     "Payment failure scare tactic detected"),

    (re.compile(r"\bwithin\s+\d+\s*(hours?|minutes?|hrs?|mins?|h)\b", re.IGNORECASE),
     "Time-pressure tactic detected (deadline threat)"),

    (re.compile(r"\bclick\s*(here|:)\b", re.IGNORECASE),
     "Call-to-action link prompt detected ('Click:' / 'Click here')"),

    (re.compile(r"\b(credited|credited\s+with|deposited|added|claimed|won)\b", re.IGNORECASE),
     "Financial credit / deposit notification lure detected"),

    (re.compile(r"\b(vip|mystery|bonus|reward|rewards|jackpot|prize|lottery|lucky)\b", re.IGNORECASE),
     "Gambling / promotional reward lure detected"),

    (re.compile(r"\b(ssn|social\s+security|credit\s+card|cvv|pin)\b", re.IGNORECASE),
     "Sensitive financial/identity data request"),

    (re.compile(r"\b(immediately|act\s+now|action\s+required)\b", re.IGNORECASE),
     "High-pressure action phrase detected"),
]


def check_rules(text: str) -> list[str]:
    """
    Run rule-based pattern matching against text.
    Returns a list of human-readable risk flags found.
    """
    if not text:
        return []

    flags = []
    for pattern, label in PHISHING_PATTERNS:
        if pattern.search(text):
            flags.append(label)

    return flags
