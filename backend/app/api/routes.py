"""
API Routes — the AI Firewall's public surface.

Zero-Trust enforcement lives here:
  1. /analyze MUST be called before /send.
  2. /send re-validates that the submitted prompt hash matches (or is a
     masked derivative of) what was analyzed — a client can't skip the
     gate by calling /send directly with an unanalyzed prompt.
  3. LLM responses are re-scanned (Output Guard) before being returned.
"""
import hashlib
import uuid
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse, SendRequest, SendResponse,
    MaskRequest, MaskResponse, AuditLogEntry, DetectedEntity,
)
from app.analyzers.pipeline import pipeline
from app.analyzers.attachment_scanner import AttachmentScannerAnalyzer
from app.risk.risk_engine import risk_engine
from app.policy.policy_engine import policy_engine
from app.remediation.masker import mask_text
from app.llm.router import llm_router
from app.db.database import get_db
from app.db.models import AuditLog
from app.utils.auth import verify_api_key
from app.config import settings

router = APIRouter()

# In-memory session store: request_id -> {prompt_hash, findings, masked_prompt}
# A real deployment would put this in Redis with a TTL.
_ANALYSIS_CACHE: Dict[str, dict] = {}

attachment_scanner = AttachmentScannerAnalyzer()


def _hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode()).hexdigest()


def _build_recommendations(findings, violations) -> list[str]:
    recs = []
    for f in findings:
        if not f.passed and f.recommendation:
            recs.append(f.recommendation)
    for v in violations:
        recs.append(f"Policy '{v.policy_name}' triggered: {v.description}")
    # de-dupe, preserve order
    return list(dict.fromkeys(recs))


@router.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(verify_api_key)])
async def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)):
    request_id = str(uuid.uuid4())

    findings = pipeline.run(req.prompt)
    risk = risk_engine.compute(findings)
    policy_result = policy_engine.evaluate(findings)

    decision = policy_result["decision"]
    # Even with no hard policy violation, a very high heuristic risk score blocks.
    if decision == "ALLOW" and risk["score"] >= settings.RISK_BLOCK_THRESHOLD:
        decision = "BLOCK"
    elif decision == "ALLOW" and risk["score"] >= settings.RISK_WARN_THRESHOLD:
        decision = "WARN"

    send_enabled = decision != "BLOCK"

    masked_prompt, masked_count = mask_text(req.prompt, findings)

    _ANALYSIS_CACHE[request_id] = {
        "prompt_hash": _hash_prompt(req.prompt),
        "masked_prompt": masked_prompt,
        "decision": decision,
        "findings": findings,
    }

    entity_types = list(risk["entity_summary"].keys())
    log = AuditLog(
        request_id=request_id,
        decision=decision,
        risk_score=risk["score"],
        risk_level=risk["level"].value,
        entity_types=entity_types,
        policy_violations=[v.policy_name for v in policy_result["violations"]],
        provider=req.provider,
        model=req.model,
        prompt_char_count=len(req.prompt),
        was_sent=False,
    )
    db.add(log)
    db.commit()

    return AnalyzeResponse(
        request_id=request_id,
        risk_score=risk["score"],
        risk_level=risk["level"],
        decision=decision,
        send_enabled=send_enabled,
        findings=findings,
        policy_violations=policy_result["violations"],
        detected_entity_summary=risk["entity_summary"],
        recommendations=_build_recommendations(findings, policy_result["violations"]),
        masked_prompt_preview=masked_prompt if masked_count > 0 else None,
        auto_fix_available=masked_count > 0,
    )


@router.post("/analyze-file", response_model=AnalyzeResponse, dependencies=[Depends(verify_api_key)])
async def analyze_file(prompt: str = Form(""), file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_MB}MB limit.")

    file_finding = attachment_scanner.scan_file(file.filename, content)

    # Best-effort text extraction for plain-text-like files; binary formats
    # (pdf/docx/xlsx) are Phase 2 (see docs/roadmap.md for the OCR/parsing hook).
    try:
        extracted_text = content.decode("utf-8", errors="ignore")
    except Exception:
        extracted_text = ""

    combined_text = f"{prompt}\n{extracted_text}"
    findings = pipeline.run(combined_text, filename=file.filename)
    findings.append(file_finding)

    risk = risk_engine.compute(findings)
    policy_result = policy_engine.evaluate(findings)
    decision = policy_result["decision"]
    if decision == "ALLOW" and risk["score"] >= settings.RISK_BLOCK_THRESHOLD:
        decision = "BLOCK"
    elif decision == "ALLOW" and risk["score"] >= settings.RISK_WARN_THRESHOLD:
        decision = "WARN"

    request_id = str(uuid.uuid4())
    masked_prompt, masked_count = mask_text(combined_text, findings)
    _ANALYSIS_CACHE[request_id] = {
        "prompt_hash": _hash_prompt(combined_text),
        "masked_prompt": masked_prompt,
        "decision": decision,
        "findings": findings,
    }

    entity_types = list(risk["entity_summary"].keys())
    db.add(AuditLog(
        request_id=request_id, decision=decision, risk_score=risk["score"],
        risk_level=risk["level"].value, entity_types=entity_types,
        policy_violations=[v.policy_name for v in policy_result["violations"]],
        prompt_char_count=len(combined_text), was_sent=False,
    ))
    db.commit()

    return AnalyzeResponse(
        request_id=request_id,
        risk_score=risk["score"],
        risk_level=risk["level"],
        decision=decision,
        send_enabled=decision != "BLOCK",
        findings=findings,
        policy_violations=policy_result["violations"],
        detected_entity_summary=risk["entity_summary"],
        recommendations=_build_recommendations(findings, policy_result["violations"]),
        masked_prompt_preview=masked_prompt if masked_count > 0 else None,
        auto_fix_available=masked_count > 0,
        document_classifications=[{"filename": file.filename}],
    )


@router.post("/mask", response_model=MaskResponse, dependencies=[Depends(verify_api_key)])
async def mask(req: MaskRequest):
    findings = pipeline.run(req.prompt)
    masked, count = mask_text(req.prompt, findings)
    return MaskResponse(masked_prompt=masked, entities_masked=count)


@router.post("/send", response_model=SendResponse, dependencies=[Depends(verify_api_key)])
async def send(req: SendRequest, db: Session = Depends(get_db)):
    cached = _ANALYSIS_CACHE.get(req.request_id)
    if not cached:
        raise HTTPException(400, "No prior /analyze call found for this request_id. Zero-Trust policy requires analysis before send.")

    if cached["decision"] == "BLOCK" and not req.use_masked_version:
        raise HTTPException(403, "This prompt was BLOCKED by policy. Apply masking or revise the prompt before sending.")

    outbound_prompt = cached["masked_prompt"] if req.use_masked_version else req.prompt

    # Re-verify: if using the raw (non-masked) prompt, it must match what was analyzed.
    if not req.use_masked_version and _hash_prompt(req.prompt) != cached["prompt_hash"]:
        raise HTTPException(409, "Prompt has changed since analysis. Please re-run Analyze before sending.")

    try:
        response_text, provider_used, model_used = await llm_router.route(
            outbound_prompt, req.provider, req.model
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(502, str(exc))

    # Output Guard: scan the LLM's response before returning it to the user.
    output_findings = pipeline.run(response_text)
    flagged = [f for f in output_findings if not f.passed]
    was_sanitized = False
    if flagged:
        response_text, _ = mask_text(response_text, output_findings)
        was_sanitized = True

    log = db.query(AuditLog).filter(AuditLog.request_id == req.request_id).first()
    if log:
        log.was_sent = True
        log.provider = provider_used
        log.model = model_used
        db.commit()

    return SendResponse(
        response_text=response_text,
        provider_used=provider_used,
        model_used=model_used,
        output_flags=flagged,
        was_sanitized=was_sanitized,
    )


@router.get("/audit-logs", dependencies=[Depends(verify_api_key)])
async def get_audit_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": l.id, "request_id": l.request_id, "timestamp": l.timestamp,
            "decision": l.decision, "risk_score": l.risk_score, "risk_level": l.risk_level,
            "entity_types": l.entity_types, "policy_violations": l.policy_violations,
            "provider": l.provider, "model": l.model, "was_sent": l.was_sent,
        }
        for l in logs
    ]


@router.get("/dashboard/summary", dependencies=[Depends(verify_api_key)])
async def dashboard_summary(db: Session = Depends(get_db)):
    logs = db.query(AuditLog).all()
    total = len(logs)
    blocked = sum(1 for l in logs if l.decision == "BLOCK")
    warned = sum(1 for l in logs if l.decision == "WARN")
    allowed = sum(1 for l in logs if l.decision == "ALLOW")

    entity_counts: Dict[str, int] = {}
    policy_counts: Dict[str, int] = {}
    for l in logs:
        for et in (l.entity_types or []):
            entity_counts[et] = entity_counts.get(et, 0) + 1
        for pv in (l.policy_violations or []):
            policy_counts[pv] = policy_counts.get(pv, 0) + 1

    return {
        "requests_processed": total,
        "blocked": blocked,
        "warned": warned,
        "allowed": allowed,
        "top_detected_entities": sorted(entity_counts.items(), key=lambda x: -x[1])[:10],
        "top_policy_violations": sorted(policy_counts.items(), key=lambda x: -x[1])[:10],
    }


@router.get("/policies", dependencies=[Depends(verify_api_key)])
async def get_policies():
    return policy_engine.list_policies()


@router.put("/policies", dependencies=[Depends(verify_api_key)])
async def update_policies(policies: list[dict]):
    policy_engine.save_policies(policies)
    return {"status": "saved", "count": len(policies)}


@router.get("/health")
async def health():
    return {"status": "ok", "service": "SecurePrompt AI Gateway"}
