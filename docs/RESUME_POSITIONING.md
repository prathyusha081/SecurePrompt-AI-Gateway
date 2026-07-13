# Positioning this project for recruiters / interviews

## Resume bullets (pick 2-3, tailor per role)

- Designed and built **SecurePrompt AI Gateway**, an open-source Zero-Trust DLP
  firewall for LLM applications that inspects prompts and attachments for
  PII/PHI, credentials, and prompt-injection/jailbreak attempts before they
  reach any model, using a configurable YAML policy engine and multi-analyzer
  detection pipeline (Strategy pattern, 6+ independent analyzers).
- Built a provider-agnostic **LLM routing layer** (Adapter/Factory pattern)
  supporting local open-source models via Ollama and hosted inference via
  Groq/OpenAI-compatible APIs, with zero code changes required to add a new
  provider.
- Implemented **Zero-Trust request verification**: server-side enforcement
  that no prompt reaches an LLM without passing a risk-scored analysis gate,
  with prompt-hash re-validation to prevent client-side bypass.
- Shipped a **risk-scoring and auto-remediation engine** that classifies
  detected sensitive entities by severity/confidence, computes a 0-100 risk
  score, and offers one-click masking/redaction before send.
- Deployed the system end-to-end on free-tier infrastructure (Render +
  Netlify + Groq), with CI (GitHub Actions), Docker Compose, and audit
  logging that never persists raw sensitive prompt content.

## How this complements your IAM/PBAC background

Your day job is PBAC policy engineering at enterprise scale (PlainID, 200+
apps). This project is the same discipline applied to a newer attack
surface: instead of "who can access this application," it's "what data is
allowed to leave this boundary toward an LLM." In interviews, you can frame
it as:

> "My day-to-day work is building policy-based access control for enterprise
> identity — deciding who can do what, under which conditions. This project
> applies the same policy-engine mindset (declarative rules, no-code policy
> changes, audit trails) to AI/LLM data governance, which is where a lot of
> enterprises are exposed right now."

That's a genuinely differentiated story: most GenAI portfolio projects are
chatbots; this one is a governance/security control plane, which lines up
directly with IAM + AI-adjacent security roles (the kind of roles you've
been targeting at GE HealthCare, Amazon, Deloitte).

## Honest scope notes (say these proactively if asked "is this production ready")

- Detection is regex/heuristic-based today, not a trained NER model — you
  know the gap and the fix (Presidio/GLiNER), which is a better signal than
  pretending it's complete.
- Auth is a single shared API key for demo purposes; you'd swap in JWT+RBAC
  (which you already have hands-on PBAC/IAM depth to speak to) before any
  real deployment.
- The public demo is free-tier hosted (Render free web service + Groq free
  inference), which means cold starts (~30-50s) after idle — mention this
  proactively so it doesn't look broken to a recruiter clicking the link.

## Suggested demo script (30-60 seconds)

1. Open the live link. Point out the Analyze/Send split — "nothing reaches
   the model without passing through the gate."
2. Paste a prompt with an Aadhaar number + "confidential payroll data."
   Click Analyze → show the blocked risk report, policy names, Send disabled.
3. Click "Mask Sensitive Data" → show the redacted preview → Send Masked.
4. Switch to the Dashboard tab → show the risk trend / top-entities charts
   building up in real time as more prompts get analyzed.
5. One line on architecture: "Strategy pattern for analyzers, Adapter/Factory
   for LLM providers, YAML policy engine — swapping in a new model or a new
   detector is a one-file change, no core logic touched."
