"""
Adapter pattern: every LLM provider implements this same interface so
the router/gateway code never has to know which backend it's talking to.
Adding a new provider = one new file implementing generate().
"""
from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    provider_name: str = "base"

    @abstractmethod
    async def generate(self, prompt: str, model: str | None = None) -> str:
        raise NotImplementedError
