"""
ORM models. Per Zero-Trust/DLP requirement: we NEVER persist the raw
prompt text or raw attachment content of a BLOCKED request — only
metadata (risk score, entity *types* found, decision, timing). Allowed/
sent requests store a truncated, non-sensitive preview only.
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean
from datetime import datetime
from app.db.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    decision = Column(String)          # BLOCK / WARN / ALLOW
    risk_score = Column(Integer)
    risk_level = Column(String)
    entity_types = Column(JSON, default=list)     # entity *type names* only, never values
    policy_violations = Column(JSON, default=list)  # policy names only
    provider = Column(String, nullable=True)
    model = Column(String, nullable=True)
    prompt_char_count = Column(Integer, default=0)  # length only, not content
    was_sent = Column(Boolean, default=False)
    user = Column(String, default="local-user")


class PolicyDecisionLog(Base):
    __tablename__ = "policy_decisions"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, index=True)
    policy_name = Column(String)
    action = Column(String)
    triggered_by = Column(JSON, default=list)
    timestamp = Column(DateTime, default=datetime.utcnow)
