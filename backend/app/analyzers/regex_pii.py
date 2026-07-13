"""
Analyzer 1: Regex Engine
Detects structured PII/PHI: email, phone, SSN, Aadhaar, PAN, Passport,
credit cards (Luhn-validated), bank accounts/IFSC, URLs, IPs.
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity

PATTERNS = {
    "EMAIL": (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", Severity.MEDIUM),
    "PHONE_IN": (r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)", Severity.MEDIUM),
    "PHONE_INTL": (r"(?<!\d)\+?\d{1,3}[-\s]?\(?\d{2,4}\)?[-\s]?\d{3,4}[-\s]?\d{3,4}(?!\d)", Severity.LOW),
    "SSN_US": (r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", Severity.CRITICAL),
    "AADHAAR": (r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)", Severity.CRITICAL),
    "PAN_CARD": (r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])", Severity.CRITICAL),
    "PASSPORT_IN": (r"(?<![A-Z0-9])[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9](?![A-Z0-9])", Severity.CRITICAL),
    "IFSC_CODE": (r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])", Severity.HIGH),
    "CREDIT_CARD": (r"(?<!\d)(?:\d[ -]*?){13,16}(?!\d)", Severity.CRITICAL),
    "BANK_ACCOUNT": (r"(?<!\d)\d{9,18}(?!\d)", Severity.HIGH),
    "IP_ADDRESS": (r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", Severity.LOW),
    "URL": (r"https?://[^\s\"'<>]+", Severity.INFO),
    "PASSWORD_FIELD": (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", Severity.CRITICAL),
}


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class RegexPIIAnalyzer(BaseAnalyzer):
    name = "regex_pii_engine"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        entities = []
        evidence = []

        for entity_type, (pattern, severity) in PATTERNS.items():
            for match in re.finditer(pattern, text):
                value = match.group()

                # Reduce false positives for numeric-heavy patterns
                if entity_type == "CREDIT_CARD" and not _luhn_valid(value):
                    continue
                if entity_type == "BANK_ACCOUNT" and (
                    _luhn_valid(value) or len(re.sub(r"\D", "", value)) < 9
                ):
                    # skip if it looks like a credit card, or too short
                    continue

                entities.append(DetectedEntity(
                    entity_type=entity_type,
                    value_preview=self._mask_preview(value),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.85,
                    source=self.name,
                ))
                evidence.append(f"{entity_type} pattern matched")

        if not entities:
            return AnalyzerFinding(
                analyzer_name=self.name, severity=Severity.INFO,
                confidence=1.0, passed=True, recommendation=None,
            )

        highest = max(entities, key=lambda e: _SEVERITY_RANK[PATTERNS[e.entity_type][1]])
        top_severity = PATTERNS[highest.entity_type][1]

        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=top_severity,
            confidence=0.85,
            evidence=list(dict.fromkeys(evidence))[:15],
            entities=entities,
            recommendation="Remove or mask the detected structured PII/PHI values before sending.",
            passed=False,
        )


_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}
