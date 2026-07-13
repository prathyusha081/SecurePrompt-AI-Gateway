"""
Risk Engine
Combines all AnalyzerFindings into a single 0-100 risk score + level.
Weighting is intentionally simple and centralized here so it's easy to
tune without touching analyzer code.
"""
from typing import List, Dict
from app.models.schemas import AnalyzerFinding, Severity, RiskLevel

SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 20,
    Severity.HIGH: 35,
    Severity.CRITICAL: 55,
}


class RiskEngine:
    def compute(self, findings: List[AnalyzerFinding]) -> Dict:
        score = 0
        for f in findings:
            if f.passed:
                continue
            base = SEVERITY_WEIGHTS[f.severity]
            # More entities of concern from one analyzer nudges the score up,
            # but with diminishing returns so one analyzer can't alone hit 100.
            entity_bonus = min(len(f.entities) * 2, 15)
            score += base * f.confidence + entity_bonus

        score = int(min(score, 100))

        if score >= 75:
            level = RiskLevel.CRITICAL
        elif score >= 50:
            level = RiskLevel.HIGH
        elif score >= 25:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        entity_summary: Dict[str, int] = {}
        for f in findings:
            for e in f.entities:
                entity_summary[e.entity_type] = entity_summary.get(e.entity_type, 0) + 1

        return {
            "score": score,
            "level": level,
            "entity_summary": entity_summary,
        }


risk_engine = RiskEngine()
