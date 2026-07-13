"""
Strategy pattern: every analyzer implements the same interface so the
AnalysisPipeline can run them uniformly and the RiskEngine can combine
their outputs without caring about internals.
"""
from abc import ABC, abstractmethod
from app.models.schemas import AnalyzerFinding


class BaseAnalyzer(ABC):
    name: str = "base_analyzer"

    @abstractmethod
    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        """Run this analyzer against text (prompt or extracted file text)."""
        raise NotImplementedError

    def _mask_preview(self, value: str, keep: int = 2) -> str:
        """Never return raw sensitive values in findings — only a masked preview."""
        if len(value) <= keep * 2:
            return "*" * len(value)
        return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]
