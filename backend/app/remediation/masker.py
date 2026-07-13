"""
Auto-Remediation: Masking Engine
Replaces detected sensitive spans in the original text with type-aware
masks (e.g. an email becomes "****@domain.com" style previews already
computed by analyzers). Operates on (start, end) offsets collected from
findings, so it never needs to re-run regexes itself.
"""
from typing import List, Tuple
from app.models.schemas import AnalyzerFinding

MASK_CHAR = "*"


def _mask_value(entity_type: str, original: str) -> str:
    if entity_type == "EMAIL" and "@" in original:
        domain = original.split("@")[-1]
        return f"{MASK_CHAR * 4}@{domain}"
    if entity_type in ("PHONE_IN", "PHONE_INTL"):
        return MASK_CHAR * (len(original) - 2) + original[-2:]
    return MASK_CHAR * len(original)


def mask_text(original_text: str, findings: List[AnalyzerFinding]) -> Tuple[str, int]:
    spans: List[Tuple[int, int, str]] = []
    for f in findings:
        for e in f.entities:
            if e.start is not None and e.end is not None:
                spans.append((e.start, e.end, e.entity_type))

    if not spans:
        return original_text, 0

    # Merge/sort spans, resolve overlaps by keeping the first (widest scan order)
    spans.sort(key=lambda s: s[0])
    merged: List[Tuple[int, int, str]] = []
    for span in spans:
        if merged and span[0] < merged[-1][1]:
            continue  # overlapping — skip, already covered
        merged.append(span)

    result = []
    cursor = 0
    for start, end, entity_type in merged:
        result.append(original_text[cursor:start])
        original_value = original_text[start:end]
        result.append(_mask_value(entity_type, original_value))
        cursor = end
    result.append(original_text[cursor:])

    return "".join(result), len(merged)
