"""
Settings from environment variables, or from backend/.env during local
development (see .env.example), plus the fixed limits the app enforces.
"""

from pathlib import Path

from pydantic import Field, SecretStr
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
    # SR-04: fixed from issue; only an explicit extension starts a new one
    session_minutes: int = 10
    # SR-04: extensions allowed per sign in, so a session lasts at most (1 + this) x SESSION_MINUTES
    max_session_extensions: int = 2
    # SR-04: how long the session survives once a ballot is accepted (safe retry and receipt only)
    post_ballot_session_seconds: int = 60

    # Root secret. app/security.py derives a separate key from it for each purpose.
    secret_key: SecretStr = Field(min_length=32)

    # SR-01: consecutive failed sign-in attempts (password or code) before the account locks, and for how long
    max_failed_attempts: int = 5
    lock_minutes: int = 15
    # SR-01: minutes allowed between the password step and the code step of sign in
    # SR-04: default lowered from 5 to 2
    mfa_pending_minutes: int = 2
    # SR-01: sign-in requests allowed per client IP in each window
    rate_limit_attempts: int = 20
    rate_limit_window_seconds: int = 300
    # SR-01: marks the session cookie Secure. Set false only for local http:// development.
    cookie_secure: bool = True

    # SR-02: the Ed25519 public key that checks electoral roll signatures. The API never holds the private key.
    roll_public_key_path: Path = BACKEND_DIR / "keys" / "roll_public.pem"
    # SR-02: minimum age on the election's polling date
    min_voting_age: int = 18

    # SR-03: a ballot token must be used within this many minutes of being issued
    ballot_token_minutes: int = 10

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

# Registration (app/routers/register.py)
REGISTRATION_SESSION_MINUTES = 10
# Wrong enrolment codes before a roll entry's code is locked
ENROLMENT_CODE_MAX_ATTEMPTS = 5
# Wrong authenticator codes before a registration in progress is ended
REGISTRATION_CODE_MAX_ATTEMPTS = 5
# Requests to /api/register/verify allowed per window, per client IP and per roll entry
# SR-01: renamed from RATE_LIMIT_WINDOW_SECONDS, now the sign-in setting above. Value unchanged.
REGISTER_VERIFY_WINDOW_SECONDS = 15 * 60
REGISTER_VERIFY_LIMIT_PER_IP = 20
REGISTER_VERIFY_LIMIT_PER_ENTRY = 10
USERNAME_PATTERN = r"[A-Za-z0-9._]{3,32}"
PASSWORD_MIN_LENGTH = 12

# Authenticator apps (TOTP)
TOTP_ISSUER = "Australian E-Voting Platform"
# Accept a code from one 30-second step either side, for clock drift on the phone
TOTP_VALID_WINDOW = 1
