"""
Attachment Scanner (heuristic malware/executable screening)
Rejects clearly dangerous file types outright and flags suspicious
indicators (macro markers, embedded script tags) in otherwise-allowed
document types. This is NOT a substitute for a real AV/sandbox engine —
for production, route allowed files through ClamAV / a cloud AV API
before this analyzer returns "passed".
"""
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity
from app.config import settings

MACRO_MARKERS = [b"VBA", b"Auto_Open", b"Auto_Close", b"Shell(", b"WScript.Shell"]
SCRIPT_MARKERS = [b"<script", b"powershell -", b"cmd.exe /c", b"eval(base64_decode"]


class AttachmentScannerAnalyzer(BaseAnalyzer):
    name = "attachment_scanner"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        # Not used for prompt text — see scan_file() for actual file bytes.
        return AnalyzerFinding(analyzer_name=self.name, severity=Severity.INFO, confidence=1.0, passed=True)

    def scan_file(self, filename: str, content: bytes) -> AnalyzerFinding:
        ext = ("." + filename.lower().rsplit(".", 1)[-1]) if "." in filename else ""
        entities = []
        evidence = []

        if ext in settings.BLOCKED_EXTENSIONS:
            entities.append(DetectedEntity(
                entity_type="BLOCKED_FILE_TYPE",
                value_preview=ext,
                confidence=1.0,
                source=self.name,
            ))
            return AnalyzerFinding(
                analyzer_name=self.name, severity=Severity.CRITICAL, confidence=1.0,
                evidence=[f"Executable/script file type blocked: {ext}"],
                entities=entities,
                recommendation="Executable and script file types are never allowed as attachments.",
                passed=False,
            )

        if ext not in settings.ALLOWED_EXTENSIONS:
            entities.append(DetectedEntity(
                entity_type="UNRECOGNIZED_FILE_TYPE", value_preview=ext, confidence=0.7, source=self.name,
            ))
            evidence.append(f"File type {ext} is not on the allow-list")

        for marker in MACRO_MARKERS:
            if marker in content:
                entities.append(DetectedEntity(
                    entity_type="SUSPICIOUS_MACRO_INDICATOR",
                    value_preview=marker.decode(errors="ignore"),
                    confidence=0.7, source=self.name,
                ))
                evidence.append("Possible macro/auto-execute indicator found")

        for marker in SCRIPT_MARKERS:
            if marker in content:
                entities.append(DetectedEntity(
                    entity_type="EMBEDDED_SCRIPT_INDICATOR",
                    value_preview=marker.decode(errors="ignore"),
                    confidence=0.7, source=self.name,
                ))
                evidence.append("Possible embedded script indicator found")

        if not entities:
            return AnalyzerFinding(analyzer_name=self.name, severity=Severity.INFO, confidence=1.0, passed=True)

        severity = Severity.HIGH if any(
            e.entity_type in ("SUSPICIOUS_MACRO_INDICATOR", "EMBEDDED_SCRIPT_INDICATOR") for e in entities
        ) else Severity.LOW

        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=severity,
            confidence=0.7,
            evidence=evidence,
            entities=entities,
            recommendation="Review the file manually or route through a full AV/sandbox engine before allowing.",
            passed=False,
        )
