"""
OpenAI-compatible Provider.
Works with OpenAI directly, and with any other vendor that exposes an
OpenAI-compatible /chat/completions endpoint (many cloud + local model
servers do, e.g. vLLM, LM Studio, OpenRouter) by just changing
OPENAI_BASE_URL in config/.env.
"""
import httpx
from app.llm.base_provider import BaseLLMProvider
from app.config import settings


class OpenAIProvider(BaseLLMProvider):
    provider_name = "openai"

    async def generate(self, prompt: str, model: str | None = None) -> str:
        if not settings.OPENAI_API_KEY:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Add it to backend/.env to use this provider."
            )
        model = model or settings.OPENAI_DEFAULT_MODEL
        url = f"{settings.OPENAI_BASE_URL}/chat/completions"
        headers = {"Authorization": f"Bearer {settings.OPENAI_API_KEY}"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
