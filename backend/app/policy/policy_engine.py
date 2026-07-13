"""
Policy Engine
Loads policies.yaml (hot-reloaded each call) and evaluates detected
entity types against it to produce a final decision: BLOCK / WARN / ALLOW.
Policies are data, not code — this is the whole point of a configurable
DLP policy layer.
"""
import yaml
from typing import List, Dict
from app.config import settings
from app.models.schemas import AnalyzerFinding, PolicyViolation


class PolicyEngine:
    def __init__(self, policy_file: str):
        self.policy_file = policy_file

    def _load(self) -> List[Dict]:
        with open(self.policy_file, "r") as f:
            data = yaml.safe_load(f)
        return data.get("policies", [])

    def evaluate(self, findings: List[AnalyzerFinding]) -> Dict:
        policies = self._load()
        entity_types_present = set()
        for f in findings:
            for e in f.entities:
                entity_types_present.add(e.entity_type)

        violations: List[PolicyViolation] = []
        decision = "ALLOW"

        for policy in policies:
            action = policy.get("action")
            if action == "ALLOW_IF_MASKED":
                continue  # handled separately by the masking flow

            matched_types = set(policy.get("match_entity_types", []))
            prefix = policy.get("match_entity_types_prefix")

            triggered = list(matched_types & entity_types_present)
            if prefix:
                triggered += [t for t in entity_types_present if t.startswith(prefix)]

            if triggered:
                violations.append(PolicyViolation(
                    policy_name=policy["name"],
                    description=policy["description"],
                    triggered_by=triggered,
                ))
                if action == "BLOCK":
                    decision = "BLOCK"
                elif action == "WARN" and decision != "BLOCK":
                    decision = "WARN"

        return {"decision": decision, "violations": violations}

    def list_policies(self) -> List[Dict]:
        return self._load()

    def save_policies(self, policies: List[Dict]) -> None:
        with open(self.policy_file, "w") as f:
            yaml.safe_dump({"policies": policies}, f, sort_keys=False)


policy_engine = PolicyEngine(settings.POLICY_FILE)
