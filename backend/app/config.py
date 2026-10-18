"""
Settings. Every value comes from an environment variable, or from backend/.env
during local development. See .env.example for the full list.
"""

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Not "localhost": on Windows that tries IPv6 first and can stall each connection
    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5432
    postgres_db: str = "evoting"
    postgres_test_db: str = "evoting_test"
    postgres_user: str = "evoting"
    # No default, so the app refuses to start without a password
    postgres_password: SecretStr

    # How long a signed-in session lasts. Keep it equal to VITE_SESSION_MINUTES in the frontend.
    session_minutes: int = 10

    def database_url(self, database: str | None = None) -> URL:
        """Connection URL for the app database, or for another database on the same server."""
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=database or self.postgres_db,
        )


settings = Settings()
