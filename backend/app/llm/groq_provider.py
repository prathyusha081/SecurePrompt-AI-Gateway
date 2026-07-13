"""
Groq Provider — free-tier hosted inference for open-source models
(Llama 3.1/3.3, Mixtral, Gemma2) via Groq's OpenAI-compatible API.

Why this exists: it lets a public demo deployment serve real, fast,
high-performing open-source LLM responses WITHOUT the deployer having to
run their own GPU server. Get a free key at https://console.groq.com/keys
"""
import httpx
from app.llm.base_provider import BaseLLMProvider
from app.config import settings


class GroqProvider(BaseLLMProvider):
    provider_name = "groq"

    async def generate(self, prompt: str, model: str | None = None) -> str:
        if not settings.GROQ_API_KEY:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Get a free key at https://console.groq.com/keys "
                "and add it to backend/.env."
            )
        model = model or settings.GROQ_DEFAULT_MODEL
        url = f"{settings.GROQ_BASE_URL}/chat/completions"
        headers = {"Authorization": f"Bearer {settings.GROQ_API_KEY}"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
