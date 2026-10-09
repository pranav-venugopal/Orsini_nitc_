from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from pydantic import field_validator
import secrets


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    model_mode: str = "mock"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    db_path: str = "events.db"
    qwen_model_id: str = "Qwen/Qwen2.5-3B-Instruct"
    guard_model_id: str = "meta-llama/Llama-Guard-3-1B"
    max_request_bytes: int = Field(default=16_384, gt=0)
    chat_rate_limit: int = Field(default=120, gt=0)
    chat_rate_window_seconds: int = Field(default=60, gt=0)
    auth_rate_limit: int = Field(default=10, gt=0)
    auth_rate_window_seconds: int = Field(default=60, gt=0)
    admin_username: str | None = None
    admin_password: str | None = None
    member_username: str | None = None
    member_password: str | None = None
    jwt_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(48), min_length=32)
    access_token_minutes: int = Field(default=480, gt=0)

    @field_validator("model_mode", mode="before")
    @classmethod
    def validate_model_mode(cls, value: str) -> str:
        mode = value.strip().lower()
        if mode == "real":
            return "local"
        if mode not in {"mock", "local"}:
            raise ValueError("MODEL_MODE must be 'mock' or 'local'.")
        return mode

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
