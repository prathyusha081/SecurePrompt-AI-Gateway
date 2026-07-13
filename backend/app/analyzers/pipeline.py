"""
AnalysisPipeline
Runs every registered analyzer (Strategy pattern) against a piece of
text and returns the combined list of findings. Adding a new analyzer
is a one-line registration here — no other code changes needed.
"""
from typing import List
from app.analyzers.regex_pii import RegexPIIAnalyzer
from app.analyzers.secrets_detector import SecretsDetectorAnalyzer
from app.analyzers.prompt_injection import PromptInjectionAnalyzer
from app.analyzers.jailbreak import JailbreakAnalyzer
from app.analyzers.doc_classifier import DocumentClassifierAnalyzer
from app.analyzers.toxicity import ToxicityAnalyzer
from app.models.schemas import AnalyzerFinding


class AnalysisPipeline:
    def __init__(self):
        self._analyzers = [
            RegexPIIAnalyzer(),
            SecretsDetectorAnalyzer(),
            PromptInjectionAnalyzer(),
            JailbreakAnalyzer(),
            DocumentClassifierAnalyzer(),
            ToxicityAnalyzer(),
        ]

    def run(self, text: str, filename: str | None = None) -> List[AnalyzerFinding]:
        return [analyzer.analyze(text, filename) for analyzer in self._analyzers]


pipeline = AnalysisPipeline()
