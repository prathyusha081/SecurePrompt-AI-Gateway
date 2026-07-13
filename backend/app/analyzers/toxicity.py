"""
Toxicity Detection Analyzer (heuristic baseline)
A lightweight keyword/pattern baseline for abusive or unsafe prompts.
NOTE: This is intentionally basic — for production accuracy, swap in a
trained classifier (e.g. Detoxify / Perspective API) behind the same
BaseAnalyzer interface. Kept generic on purpose (no slur lists shipped).
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity

# Category-level patterns only — intentionally coarse, not a slur database.
ABUSE_PATTERNS = {
    "THREATENING_LANGUAGE": r"\b(i will (kill|hurt|destroy) you|i'm going to (kill|hurt) you)\b",
    "HARASSMENT_INTENT": r"\b(you are (worthless|pathetic|garbage) and should)\b",
}
COMPILED = {k: re.compile(v, re.IGNORECASE) for k, v in ABUSE_PATTERNS.items()}


class ToxicityAnalyzer(BaseAnalyzer):
    name = "toxicity_detector"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        entities = []
        evidence = []
        for label, pattern in COMPILED.items():
            for match in pattern.finditer(text):
                entities.append(DetectedEntity(
                    entity_type=f"TOXIC_{label}",
                    value_preview=self._mask_preview(match.group(), keep=3),
                    confidence=0.6,
                    source=self.name,
                ))
                evidence.append(f"Potential abusive content: {label}")

        if not entities:
            return AnalyzerFinding(analyzer_name=self.name, severity=Severity.INFO, confidence=1.0, passed=True)

        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=Severity.MEDIUM,
            confidence=0.6,
            evidence=evidence,
            entities=entities,
            recommendation="Review prompt for abusive/unsafe language before sending.",
            passed=False,
        )
