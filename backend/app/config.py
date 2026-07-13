"""
Central application configuration.
All values are overridable via environment variables (.env file supported).
"""
from pydantic_settings import BaseSettings
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "SecurePrompt AI Gateway"
    ENV: str = "development"

    # --- Auth ---
    JWT_SECRET: str = "change-me-in-production-please"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 8
    API_KEY: str = "dev-local-api-key"  # simple shared-secret auth for local/demo use

    # --- Database ---
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/gateway.db"

    # --- Risk thresholds ---
    RISK_BLOCK_THRESHOLD: int = 60   # >= this => Send button disabled
    RISK_WARN_THRESHOLD: int = 30    # >= this => warning shown but Send allowed

    # --- LLM providers ---
    DEFAULT_LLM_PROVIDER: str = "ollama"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_DEFAULT_MODEL: str = "llama3"

    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_DEFAULT_MODEL: str = "gpt-4o-mini"

    # Groq: free-tier hosted open-source models (Llama 3.1/3.3, Mixtral, Gemma2).
    # Recommended default for public demo deployments (no self-hosted GPU needed).
    GROQ_API_KEY: str = ""
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_DEFAULT_MODEL: str = "llama-3.1-8b-instant"

    # --- Public demo / rate limiting ---
    DEMO_MODE: bool = False              # set true on public deployments
    RATE_LIMIT_PER_MINUTE: int = 20      # per-IP request cap when DEMO_MODE is true

    # --- Uploads ---
    MAX_UPLOAD_MB: int = 15
    ALLOWED_EXTENSIONS: tuple = (
        ".txt", ".md", ".csv", ".json", ".pdf", ".docx", ".xlsx",
        ".png", ".jpg", ".jpeg", ".py", ".js", ".ts", ".java", ".yaml", ".yml"
    )
    BLOCKED_EXTENSIONS: tuple = (
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js.exe",
        ".scr", ".msi", ".jar", ".apk", ".com", ".pif"
    )

    POLICY_FILE: str = str(BASE_DIR / "app" / "policy" / "policies.yaml")

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
