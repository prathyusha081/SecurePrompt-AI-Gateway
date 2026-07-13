"""
LLM Router (Factory Pattern)
Selects the correct provider adapter based on the request, with the
default provider coming from config. Only ever called AFTER the gateway
has approved a prompt via the analyze -> policy -> risk pipeline.
"""
from app.llm.base_provider import BaseLLMProvider
from app.llm.ollama_provider import OllamaProvider
from app.llm.openai_provider import OpenAIProvider
from app.llm.groq_provider import GroqProvider
from app.config import settings

_PROVIDERS = {
    "ollama": OllamaProvider(),
    "openai": OpenAIProvider(),
    "groq": GroqProvider(),
    # Add new providers here, e.g. "claude": ClaudeProvider(), "gemini": GeminiProvider()
}


class LLMRouter:
    def get_provider(self, name: str | None = None) -> BaseLLMProvider:
        name = (name or settings.DEFAULT_LLM_PROVIDER).lower()
        provider = _PROVIDERS.get(name)
        if not provider:
            raise ValueError(f"Unknown LLM provider '{name}'. Available: {list(_PROVIDERS.keys())}")
        return provider

    async def route(self, prompt: str, provider: str | None = None, model: str | None = None) -> tuple[str, str, str]:
        adapter = self.get_provider(provider)
        response_text = await adapter.generate(prompt, model)
        defaults = {
            "ollama": settings.OLLAMA_DEFAULT_MODEL,
            "openai": settings.OPENAI_DEFAULT_MODEL,
            "groq": settings.GROQ_DEFAULT_MODEL,
        }
        used_model = model or defaults.get(adapter.provider_name, "unknown")
        return response_text, adapter.provider_name, used_model


llm_router = LLMRouter()
