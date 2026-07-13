# Architecture

## Sequence: Analyze → Send

```mermaid
sequenceDiagram
    participant U as User (Frontend)
    participant G as Gateway API
    participant P as Analysis Pipeline
    participant R as Risk Engine
    participant PE as Policy Engine
    participant L as LLM Router
    participant DB as Audit DB

    U->>G: POST /analyze {prompt}
    G->>P: run(prompt)
    P-->>G: [AnalyzerFinding...]
    G->>R: compute(findings)
    R-->>G: risk_score, risk_level
    G->>PE: evaluate(findings)
    PE-->>G: decision (ALLOW/WARN/BLOCK), violations
    G->>DB: log metadata (no raw sensitive content)
    G-->>U: risk report (send_enabled = decision != BLOCK)

    alt send_enabled == true
        U->>G: POST /send {request_id, prompt}
        G->>G: verify request_id was analyzed + hash matches
        G->>L: route(prompt, provider, model)
        L-->>G: llm response
        G->>P: run(response)  note: Output Guard
        P-->>G: output findings
        G->>G: mask response if needed
        G-->>U: sanitized response
    else send_enabled == false
        U->>G: (Send button disabled in UI)
    end
```

## Data flow

```mermaid
flowchart LR
    A[User Prompt / Attachment] --> B[Attachment Scanner]
    A --> C[Regex PII Engine]
    A --> D[Secrets Detector]
    A --> E[Prompt Injection Detector]
    A --> F[Jailbreak Detector]
    A --> G[Document Classifier]
    A --> H[Toxicity Detector]
    B & C & D & E & F & G & H --> I[Risk Engine]
    I --> J[Policy Engine]
    J -->|ALLOW/WARN| K[LLM Router]
    J -->|BLOCK| L[Blocked — never reaches LLM]
    K --> M[Output Guard]
    M --> N[Sanitized Response to User]
    I --> O[(Audit DB - metadata only)]
    J --> O
```

## Threat model (STRIDE-style, abbreviated)

| Threat | Mitigation in this project |
|---|---|
| Sensitive data (PII/PHI/secrets) sent to a third-party LLM | Regex PII engine + Secrets detector + Document classifier, enforced by Policy Engine before any LLM call |
| Prompt injection / instruction override | Prompt Injection Detector (heuristic phrase matching) |
| Jailbreak framing (DAN, dev-mode, roleplay bypass) | Jailbreak Detector, hard-BLOCK policy |
| Malicious file upload (macro, script, executable) | Attachment Scanner — extension allow/block-list + macro/script indicator scan |
| LLM response leaking sensitive data back to user | Output Guard — response is re-run through the same analyzer pipeline before being shown |
| Bypassing Analyze and calling Send directly | `/send` requires a prior `/analyze` `request_id` + prompt-hash match (Zero-Trust re-verification) |
| Sensitive prompts persisted in logs | Audit DB stores only entity *type names*, risk score, and decision — never raw prompt/attachment content |
| Unauthorized API access | `X-API-Key` header required on all gateway endpoints (swap for full JWT/RBAC in production — see roadmap) |

## What's implemented vs. roadmap (Phase 2)

**Implemented (works out of the box, no heavy ML downloads):**
Regex PII/PHI engine, Secrets detector, Prompt injection detector, Jailbreak detector,
Document classifier, Toxicity heuristic, Attachment/malware-indicator scanner, Risk engine,
YAML Policy engine, Auto-masking/remediation, LLM Router (Ollama + OpenAI-compatible),
Output Guard, SQLite audit logging, React frontend with Analyze/Send workflow, Docker Compose.

**Roadmap / Phase 2 (swap-in, same analyzer interface):**
- Microsoft Presidio + GLiNER + spaCy for statistical/NER-based PII detection (higher recall than regex alone)
- EasyOCR/Tesseract for scanned PDF/image text extraction
- Real AV/sandbox integration (ClamAV or cloud AV API) in the attachment scanner
- Postgres + Redis for production-scale storage, caching, and rate limiting
- Full JWT auth + RBAC (currently a single shared API key)
- Prometheus/Grafana/OpenTelemetry observability stack
- Kubernetes manifests / Helm chart
