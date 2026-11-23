from __future__ import annotations

CONTENT_RULES: list[dict] = [
    {
        "type": "urgency_language",
        "title": "Message uses urgency pressure",
        "severity": "medium",
        "description": "The email pressures the recipient to act quickly, a common social "
        "engineering tactic used to bypass careful decision-making.",
        "recommendation": "Slow down and verify the request through an official channel before acting.",
        "patterns": [
            r"\bimmediately\b",
            r"\burgent(ly)?\b",
            r"\bact now\b",
            r"\bwithin \d+ (hours?|minutes?|days?)\b",
            r"\bfinal (warning|notice)\b",
            r"\blast chance\b",
            r"\bexpires? (today|soon|in \d+)\b",
        ],
    },
    {
        "type": "credential_request",
        "title": "Message requests credentials",
        "severity": "high",
        "description": "The email asks the recipient to verify, confirm or re-enter account "
        "credentials. Legitimate services do not request passwords by email.",
        "recommendation": "Never submit credentials from an email link. Navigate to the service directly.",
        "patterns": [
            r"\b(verify|confirm|update|re-?enter|validate)\b.{0,40}\b(password|credentials|login|sign[- ]?in)\b",
            r"\b(password|credentials)\b.{0,40}\b(verify|confirm|update|expire|reset)\b",
            r"\bclick .{0,30}\b(verify|confirm|login|sign in)\b",
        ],
    },
    {
        "type": "otp_request",
        "title": "Message references one-time codes",
        "severity": "high",
        "description": "The email mentions OTPs or verification codes, which attackers try to "
        "harvest to bypass multi-factor authentication.",
        "recommendation": "Never share one-time codes. No legitimate support agent needs them.",
        "patterns": [
            r"\b(otp|one[- ]time (code|password)|verification code|security code|2fa code)\b",
            r"\bsend (us |me )?(the )?(code|otp)\b",
        ],
    },
    {
        "type": "payment_fraud",
        "title": "Message contains payment-related requests",
        "severity": "medium",
        "description": "The email references failed payments, billing updates or unusual money "
        "movement, patterns frequently used in payment fraud.",
        "recommendation": "Check payment status directly in the official account portal.",
        "patterns": [
            r"\bpayment (failed|declined|problem|issue)\b",
            r"\b(update|confirm).{0,30}\b(billing|payment method|card details)\b",
            r"\b(wire|bank) transfer\b",
            r"\bgift cards?\b",
            r"\brefund.{0,30}\b(required|pending|process)\b",
        ],
    },
    {
        "type": "account_suspension",
        "title": "Message threatens account suspension",
        "severity": "high",
        "description": "The email warns that an account will be suspended or closed, a classic "
        "phishing pressure tactic.",
        "recommendation": "Log in through the official website or app to check account status.",
        "patterns": [
            r"\b(account|profile|access)\b.{0,40}\b(suspend\w*|lock\w*|clos\w*|disabl\w*|deactivat\w*|restrict\w*)\b",
            r"\b(suspend\w*|lock\w*|clos\w*|disabl\w*)\b.{0,30}\b(account|profile|access)\b",
        ],
    },
    {
        "type": "financial_instruction",
        "title": "Message contains financial instructions",
        "severity": "medium",
        "description": "The email instructs the recipient to move funds or settle an invoice, "
        "which is consistent with business email compromise attempts.",
        "recommendation": "Confirm any financial instruction by phone with a known contact.",
        "patterns": [
            r"\b(transfer|send|remit)\b.{0,30}\b(funds|money|payment|\$\s?\d|usd|eur|gbp)\b",
            r"\binvoice (is )?attached\b",
            r"\boutstanding balance\b",
            r"\bpayment details (have )?changed\b",
        ],
    },
]

HTML_HIDDEN_PATTERNS = [
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"opacity\s*:\s*0(?:\.0+)?\b",
    r"font-size\s*:\s*0(?:px|em|rem)?\b",
    r"\bhidden\b",
]
