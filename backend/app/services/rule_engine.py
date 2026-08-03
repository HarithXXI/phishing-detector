"""
Rule-Based Phishing Detection Engine

Scans email/message text for phishing indicators using
deterministic pattern matching. No ML — just regex + keyword lists.
"""

import re


# Each pattern: (compiled_regex, risk_label)
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
     "VIP reward / prize / bonus scam lure detected"),

    (re.compile(r"\b(withdrawal|withdraw|cashout|claim)\s+(available|now|instant|within)\b", re.IGNORECASE),
     "Withdrawal availability / claim pressure tactic detected"),

    (re.compile(r"\b(confirm|update)\s+(your\s+)?(billing|payment|credit\s*card)\b", re.IGNORECASE),
     "Billing/payment information request detected"),

    (re.compile(r"\b(ssn|social\s+security|credit\s*card\s*number)\b", re.IGNORECASE),
     "Sensitive personal data request detected"),

    (re.compile(r"\bdear\s+(customer|user|valued\s+member|member|account\s+holder)\b", re.IGNORECASE),
     "Generic greeting detected (impersonation pattern)"),

    (re.compile(r"\b(act\s+now|immediate\s+action|action\s+required)\b", re.IGNORECASE),
     "Immediate action pressure detected"),

    (re.compile(r"\b(parcel|package|shipment|delivery)\s+(held|restricted|delayed|pending)\b", re.IGNORECASE),
     "Parcel / shipment hold scare tactic detected"),

    (re.compile(r"\b(pay\s+(rs\.?|inr|\$|usd|\€|£)?\s*\d+|payment\s+required)\b", re.IGNORECASE),
     "Unexpected fee / payment request detected"),

    (re.compile(r"\b(rs\.?|inr|\$|usd|₹)\s*[\d,]+\b", re.IGNORECASE),
     "Monetary currency / sum figure detected"),
]


def check_rules(clean_text: str) -> list[str]:
    """
    Scan text against known phishing patterns.

    Args:
        clean_text: The email body / message text to scan.

    Returns:
        List of risk description strings for every matched pattern.
    """
    risks = []
    for pattern, risk_label in PHISHING_PATTERNS:
        if pattern.search(clean_text):
            risks.append(risk_label)
    return risks
