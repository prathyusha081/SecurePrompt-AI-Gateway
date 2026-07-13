"""
Secrets Detection Analyzer
Detects cloud provider keys, private keys, tokens, connection strings.
This is the analyzer most likely to catch accidental credential leakage
into an LLM prompt (a very common real-world DLP incident).
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
    "AWS_SECRET_KEY": r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}",
    "AZURE_KEY": r"(?i)(azure|az)_?(api)?_?key\s*[:=]\s*[A-Za-z0-9+/=]{32,}",
    "GCP_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "PRIVATE_KEY_BLOCK": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "SLACK_TOKEN": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "GENERIC_API_KEY": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?",
    "DB_CONNECTION_STRING": r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis)://[^\s\"']+:[^\s\"']+@[^\s\"']+",
    "OPENAI_KEY": r"sk-[A-Za-z0-9]{20,}",
}


class SecretsDetectorAnalyzer(BaseAnalyzer):
    name = "secrets_detector"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        entities = []
        evidence = []

        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                value = match.group()
                entities.append(DetectedEntity(
                    entity_type=secret_type,
                    value_preview=self._mask_preview(value, keep=3),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.9,
                    source=self.name,
                ))
                evidence.append(f"{secret_type} detected")

        if not entities:
            return AnalyzerFinding(
                analyzer_name=self.name, severity=Severity.INFO,
                confidence=1.0, passed=True,
            )

        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=Severity.CRITICAL,
            confidence=0.9,
            evidence=list(dict.fromkeys(evidence)),
            entities=entities,
            recommendation="Rotate any real credentials matched here immediately and remove them from the prompt.",
            passed=False,
        )
