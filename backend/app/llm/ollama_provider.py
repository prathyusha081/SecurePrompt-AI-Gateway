"""
Ollama Provider — talks to a local Ollama daemon.
Works with any model you've pulled: llama3, qwen2, deepseek-r1, mistral,
gemma2, phi3, etc. Model name is just passed straight through.
"""
import httpx
from app.llm.base_provider import BaseLLMProvider
from app.config import settings


class OllamaProvider(BaseLLMProvider):
    provider_name = "ollama"

    async def generate(self, prompt: str, model: str | None = None) -> str:
        model = model or settings.OLLAMA_DEFAULT_MODEL
        url = f"{settings.OLLAMA_BASE_URL}/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False}

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "").strip()
        except httpx.ConnectError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {settings.OLLAMA_BASE_URL}. "
                f"Is `ollama serve` running and have you pulled '{model}'? "
                f"(run: ollama pull {model})"
            ) from exc
