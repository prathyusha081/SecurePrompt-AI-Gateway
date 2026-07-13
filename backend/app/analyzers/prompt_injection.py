"""
Prompt Injection Detection Analyzer
Heuristic phrase/pattern matching for direct + indirect injection attempts
aimed at overriding system instructions or exfiltrating hidden prompts.
This is intentionally a defensive *detector* — it does not execute or
demonstrate any injection technique, only flags likely attempts.
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity

INJECTION_PHRASES = [
    r"ignore (all|any|the)?\s*(previous|prior|above)\s*instructions",
    r"disregard (all|any|the)?\s*(previous|prior|above)\s*instructions",
    r"forget (all|any|the)?\s*(previous|prior|above)\s*(instructions|rules|context)",
    r"reveal (your |the )?system prompt",
    r"show (me )?(your |the )?system prompt",
    r"what (are|is) your (system )?instructions",
    r"override (the )?(safety|policy|content) (filter|policy|rules)",
    r"you are now (in )?(a )?new (mode|persona|role)",
    r"pretend (you|to) (are|be)",
    r"act as if you have no (restrictions|rules|filters)",
    r"this is a hidden (instruction|prompt)",
    r"\[system\]|\[/system\]|<system>|</system>",
    r"end of (user|system) (prompt|message)",
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PHRASES]


class PromptInjectionAnalyzer(BaseAnalyzer):
    name = "prompt_injection_detector"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        entities = []
        evidence = []

        for pattern in COMPILED:
            for match in pattern.finditer(text):
                entities.append(DetectedEntity(
                    entity_type="PROMPT_INJECTION_PHRASE",
                    value_preview=self._mask_preview(match.group(), keep=4),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.75,
                    source=self.name,
                ))
                evidence.append("Injection-style phrase detected")

        if not entities:
            return AnalyzerFinding(
                analyzer_name=self.name, severity=Severity.INFO,
                confidence=1.0, passed=True,
            )

        severity = Severity.HIGH if len(entities) > 1 else Severity.MEDIUM
        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=severity,
            confidence=0.75,
            evidence=list(dict.fromkeys(evidence)),
            entities=entities,
            recommendation="Prompt contains language typically associated with instruction-override attempts. Review before sending.",
            passed=False,
        )
