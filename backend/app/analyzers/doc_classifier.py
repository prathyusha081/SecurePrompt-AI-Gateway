"""
Document Classification Analyzer
Keyword/heuristic classification of prompt or file content into
sensitivity + content-domain buckets. This is a lightweight stand-in
for a trained classifier — swap in a fine-tuned model in Phase 2
without changing the analyzer interface.
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.schemas import AnalyzerFinding, DetectedEntity, Severity

SENSITIVITY_KEYWORDS = {
    "RESTRICTED": ["top secret", "restricted access", "board only", "eyes only"],
    "CONFIDENTIAL": ["confidential", "internal use only", "do not distribute", "nda", "proprietary"],
    "INTERNAL": ["internal", "employee only", "company confidential"],
}

DOMAIN_KEYWORDS = {
    "PAYROLL": ["payroll", "salary", "ctc", "compensation statement", "gross pay", "net pay"],
    "MEDICAL": ["diagnosis", "patient", "medical record", "prescription", "icd-10", "phi"],
    "LEGAL": ["nda", "litigation", "settlement agreement", "attorney-client", "legal privilege"],
    "FINANCIAL": ["balance sheet", "income statement", "bank statement", "revenue forecast", "invoice"],
    "SOURCE_CODE": ["import ", "def ", "function ", "class ", "public static void", "select * from"],
    "ARCHITECTURE_DOC": ["architecture diagram", "system design", "network topology", "infrastructure diagram"],
    "CUSTOMER_DATA": ["customer list", "client database", "crm export", "customer record"],
}


class DocumentClassifierAnalyzer(BaseAnalyzer):
    name = "document_classifier"

    def analyze(self, text: str, filename: str | None = None) -> AnalyzerFinding:
        lower = text.lower()
        entities = []
        evidence = []

        sensitivity = "PUBLIC"
        for level, keywords in SENSITIVITY_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                sensitivity = level
                break

        domains_found = []
        for domain, keywords in DOMAIN_KEYWORDS.items():
            hits = [kw for kw in keywords if kw in lower]
            if hits:
                domains_found.append(domain)
                entities.append(DetectedEntity(
                    entity_type=f"DOC_CLASS_{domain}",
                    value_preview=f"{len(hits)} keyword(s) matched",
                    confidence=0.6,
                    source=self.name,
                ))
                evidence.append(f"Classified as {domain} ({len(hits)} keyword matches)")

        if filename:
            ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
            if ext in ("py", "js", "ts", "java", "go", "rb", "cs", "cpp"):
                if "SOURCE_CODE" not in domains_found:
                    domains_found.append("SOURCE_CODE")
                    evidence.append("Classified as SOURCE_CODE (by file extension)")

        passed = sensitivity == "PUBLIC" and not domains_found
        severity = Severity.INFO
        if sensitivity in ("CONFIDENTIAL", "RESTRICTED") or "PAYROLL" in domains_found or "MEDICAL" in domains_found:
            severity = Severity.HIGH
        elif sensitivity == "INTERNAL" or domains_found:
            severity = Severity.MEDIUM

        return AnalyzerFinding(
            analyzer_name=self.name,
            severity=severity,
            confidence=0.7,
            evidence=evidence,
            entities=entities,
            recommendation=None if passed else f"Document classified as {sensitivity} / {', '.join(domains_found) or 'general'}.",
            passed=passed,
        )
