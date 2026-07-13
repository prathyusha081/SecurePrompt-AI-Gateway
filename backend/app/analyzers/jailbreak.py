"""
Jailbreak Detection Analyzer
Flags known jailbreak-framing patterns (DAN, developer mode, roleplay
bypass, safety-bypass requests). Detection-only — this analyzer names
the *pattern category*, not the payload, to avoid the report itself
becoming a jailbreak script.
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity

JAILBREAK_PATTERNS = {
    "DAN_STYLE": r"\bDAN\b.{0,40}(mode|do anything now)",
    "DEVELOPER_MODE": r"(developer|dev) mode\s*(enabled|on|activated)?",
    "NO_RESTRICTIONS_ROLEPLAY": r"(roleplay|pretend) .{0,40}(no (rules|restrictions|filters|limits))",
    "SAFETY_BYPASS": r"(bypass|disable|turn off) .{0,20}(safety|content) (filter|policy|guardrails?)",
    "PROMPT_LEAK_REQUEST": r"(repeat|print|output) (your |the )?(instructions|system prompt) (verbatim|exactly|word for word)",
}

COMPILED = {k: re.compile(v, re.IGNORECASE) for k, v in JAILBREAK_PATTERNS.items()}


class JailbreakAnalyzer(BaseAnalyzer):
    name = "jailbreak_detector"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        entities = []
        evidence = []

        for label, pattern in COMPILED.items():
            for match in pattern.finditer(text):
                entities.append(DetectedEntity(
                    entity_type=f"JAILBREAK_{label}",
                    value_preview=self._mask_preview(match.group(), keep=4),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.8,
                    source=self.name,
                ))
                evidence.append(f"Jailbreak pattern category: {label}")

        if not entities:
            return AnalyzerFinding(
                analyzer_name=self.name, severity=Severity.INFO,
                confidence=1.0, passed=True,
            )

        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=Severity.HIGH,
            confidence=0.8,
            evidence=list(dict.fromkeys(evidence)),
            entities=entities,
            recommendation="Prompt matches a known jailbreak-framing pattern category. Blocking recommended.",
            passed=False,
        )
