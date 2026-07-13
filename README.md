# SecurePrompt AI Gateway 🛡️

A Zero-Trust AI Gateway that inspects every prompt and attachment for PII/PHI,
secrets, prompt-injection, and jailbreak attempts **before** it reaches any LLM
— open-source, any-model (Ollama local models or OpenAI-compatible APIs).

```
Analyze → Risk Report → [Send disabled if blocked] → Send → LLM → Output Guard → Response
```

See `docs/ARCHITECTURE.md` for sequence/data-flow diagrams and the threat model,
and the bottom of that file for exactly what's implemented vs. Phase-2 roadmap items.
See `docs/RESUME_POSITIONING.md` for resume bullets and an interview demo script.

**Live demo:** deploy your own free copy in ~15 minutes — see [Section 5](#5-deploy-it-for-free-and-share-a-live-link) below.

## What's new in this version
- 📊 **Dashboard tab** — decision breakdown + top-detected-entity charts (Chart.js)
- 📜 **Audit Log tab** — recent requests with risk/decision/entities (metadata only, never raw content)
- ⚙️ **Policies tab** — live view of the YAML policy engine's active rules
- 🆓 **Groq provider** — free-tier hosted open-source models (Llama 3.1, Mixtral, Gemma2) so a public demo doesn't need a self-hosted GPU
- 🚦 **Rate limiting** — per-IP request cap when `DEMO_MODE=true`, so a free public deployment can't be abused
- 🧪 **CI** — GitHub Actions runs tests + Docker builds on every push
- 📄 **MIT licensed** — free to fork, use, and put in your portfolio

---

## 1. Project structure

```
secureprompt-ai-gateway/
├── backend/
│   ├── app/
│   │   ├── analyzers/       # Strategy-pattern analyzers (PII, secrets, injection, jailbreak, doc classifier, toxicity, attachments)
│   │   ├── risk/            # Risk scoring engine
│   │   ├── policy/          # YAML-driven policy engine
│   │   ├── remediation/     # Auto-masking
│   │   ├── llm/             # Provider adapters (Ollama, OpenAI-compatible) + Factory router
│   │   ├── db/               # SQLAlchemy models + session
│   │   ├── api/               # FastAPI routes
│   │   ├── models/            # Pydantic schemas
│   │   ├── utils/              # Auth
│   │   ├── config.py
│   │   └── main.py
│   ├── tests/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── index.html            # Single-file React app (CDN, no build step)
│   └── Dockerfile
├── docs/
│   └── ARCHITECTURE.md
├── docker-compose.yml
└── README.md
```

---

## 2. Quick start — Docker (recommended)

Requires Docker + Docker Compose.

```bash
cd secureprompt-ai-gateway
docker compose up --build
```

This starts:
- **backend** — FastAPI gateway on `http://localhost:8000` (docs at `/docs`)
- **frontend** — React UI on `http://localhost:3000`
- **ollama** — local LLM runtime on `http://localhost:11434`

Then pull a model into the Ollama container and try it:

```bash
docker exec -it secureprompt-ollama ollama pull llama3
```

Open `http://localhost:3000`, type a prompt, click **Analyze**, then **Send**.

---

## 3. Quick start — run locally without Docker

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Backend is now live at `http://localhost:8000` — interactive API docs at
`http://localhost:8000/docs`.

### LLM: install Ollama locally

```bash
# https://ollama.com/download
ollama serve
ollama pull llama3        # or: qwen2, deepseek-r1, mistral, gemma2, phi3
```

(Alternatively, set `DEFAULT_LLM_PROVIDER=openai` and `OPENAI_API_KEY` in `.env`
to use OpenAI or any OpenAI-compatible endpoint instead.)

### Frontend

No build step needed — it's a single static HTML file using React via CDN.

```bash
cd frontend
python -m http.server 3000
```

Open `http://localhost:3000`.

> If your backend isn't at `http://localhost:8000`, open the browser console
> on the frontend and set `window.SECUREPROMPT_API_BASE` before load, or edit
> the constant at the top of `index.html`.

---

## 4. Try it out

**Prompt that gets blocked:**
```
My Aadhaar number is 1234 5678 9012 and my PAN is ABCDE1234F.
This is confidential payroll data, please summarize it.
```
→ Analyze returns `risk_score ≈ 90+`, `decision: BLOCK`, Send button stays disabled,
and you'll see the exact report format:

```
Risk Score: 92/100 (CRITICAL)
Detected:
✓ AADHAAR
✓ PAN_CARD
✓ DOC_CLASS_PAYROLL
Policy Violated:
BLOCK_PII, BLOCK_FINANCIAL
Recommendation:
• Remove or mask the detected structured PII/PHI values before sending.
• Policy 'BLOCK_FINANCIAL' triggered: Block payroll, bank account, and financial-statement content.
Auto Fix Available: [Mask Sensitive Data]
```

**Prompt that's fine:**
```
Summarize the benefits of zero-trust architecture for enterprise IAM.
```
→ `risk_score` low, `decision: ALLOW`, Send enabled, goes straight to the LLM.

**Try the mask flow:** click "Mask Sensitive Data" on a blocked prompt, review
the masked preview, then click "Send Masked Version" to send the redacted text.

---

## 5. Deploy it for free and share a live link

This gets you a public URL you can put on your resume/LinkedIn, entirely on
free tiers: **Render** (backend API), **Netlify** (static frontend), **Groq**
(free hosted open-source LLM inference — no GPU server needed).

### Step 1 — Push to GitHub
```bash
cd secureprompt-ai-gateway
git init && git add . && git commit -m "Initial commit: SecurePrompt AI Gateway"
git branch -M main
git remote add origin https://github.com/<your-username>/secureprompt-ai-gateway.git
git push -u origin main
```

### Step 2 — Get a free Groq API key
1. Go to **https://console.groq.com/keys** and sign up (free, no credit card).
2. Create an API key — copy it, you'll need it in Step 3.

### Step 3 — Deploy the backend on Render (free)
1. Go to **https://dashboard.render.com** → sign up free → **New → Blueprint**.
2. Connect your GitHub repo. Render auto-detects `render.yaml` in this repo
   and provisions the service.
3. In the service's **Environment** tab, set `GROQ_API_KEY` to the key from
   Step 2 (this one field is marked `sync: false` in the blueprint so you set
   it manually — never commit API keys to git).
4. Deploy. You'll get a URL like `https://secureprompt-ai-gateway-backend.onrender.com`.
5. Note the auto-generated `API_KEY` value from the Environment tab too —
   you'll need it in Step 4.

> Free tier note: the service sleeps after 15 minutes of no traffic and takes
> ~30-50s to wake on the next request. Mention this in your demo link so it
> doesn't look broken — "first load may take ~40s, it's a free-tier cold start."

### Step 4 — Deploy the frontend on Netlify (free)
1. Edit `frontend/config.js`:
   ```js
   window.SECUREPROMPT_API_BASE = "https://secureprompt-ai-gateway-backend.onrender.com/api";
   window.SECUREPROMPT_API_KEY = "<the API_KEY from Render step 3.5>";
   window.SECUREPROMPT_DEMO_MODE = true;
   window.SECUREPROMPT_GITHUB_URL = "https://github.com/<your-username>/secureprompt-ai-gateway";
   ```
2. Commit and push that change.
3. Go to **https://app.netlify.com** → sign up free → **Add new site → Import
   from Git** → pick your repo → set **Base directory** to `frontend`.
   (Or skip Git entirely: **https://app.netlify.com/drop** and drag the
   `frontend/` folder in directly for an instant deploy.)
4. You'll get a URL like `https://secureprompt-ai-gateway.netlify.app` —
   that's your shareable link.

### Step 5 — Update CORS (optional but recommended)
In `backend/app/main.py`, change `allow_origins=["*"]` to your Netlify URL
specifically, then redeploy the backend, so only your frontend can call it.

### That's it — cost so far: $0.
Share the Netlify URL. Anyone who opens it can Analyze/Send prompts against
a real open-source LLM (via Groq), see the risk report, and click through
the Dashboard/Audit/Policies tabs — all on your free-tier deployment.

---

## 6. Running tests

```bash
cd backend
pip install pytest
pytest tests/ -v
```

Tests cover: clean-prompt low risk, Aadhaar/AWS-key detection + blocking,
prompt-injection detection, masking correctness, and default email policy.

---

## 7. Configuring policies (no code changes needed)

Edit `backend/app/policy/policies.yaml` — each policy has a `name`,
`description`, `action` (`BLOCK` / `WARN` / `ALLOW`), and the entity types
that trigger it. Reloaded automatically on the next `/analyze` call. You can
also view/update policies via `GET`/`PUT /api/policies`.

---

## 8. Adding a new LLM provider

1. Create `backend/app/llm/your_provider.py` implementing `BaseLLMProvider.generate()`.
2. Register it in `_PROVIDERS` in `backend/app/llm/router.py`.
3. Done — no other code changes needed (Adapter + Factory pattern).

## 9. Adding a new analyzer

1. Create `backend/app/analyzers/your_analyzer.py` implementing `BaseAnalyzer.analyze()`.
2. Register it in `AnalysisPipeline._analyzers` in `backend/app/analyzers/pipeline.py`.
3. Reference its entity types in `policies.yaml` if you want it enforced.

---

## 10. Security notes for anyone extending this toward production

- Replace the single shared `X-API-Key` with full JWT + RBAC.
- Move the in-memory `_ANALYSIS_CACHE` (analyze→send session state) to Redis with a TTL.
- Switch `DATABASE_URL` to Postgres.
- Route allowed attachments through a real AV/sandbox engine, not just the
  extension/macro-indicator heuristic in `attachment_scanner.py`.
- Add Presidio/GLiNER/spaCy for statistical PII detection to catch what
  regex alone misses (unstructured names, addresses, free-text PHI).
- Put this gateway behind HTTPS + a reverse proxy (Nginx/Traefik) in any real deployment.

Full roadmap detail: `docs/ARCHITECTURE.md`.
