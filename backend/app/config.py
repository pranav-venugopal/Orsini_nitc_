from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    model_mode: str = "mock"  # "mock" | "real"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    db_path: str = "events.db"
    qwen_model_id: str = "Qwen/Qwen2.5-3B-Instruct"
    guard_model_id: str = "meta-llama/Llama-Guard-3-1B"
    hf_token: str | None = None
    max_request_bytes: int = Field(default=16_384, gt=0)
    chat_rate_limit: int = Field(default=120, gt=0)
    chat_rate_window_seconds: int = Field(default=60, gt=0)

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
