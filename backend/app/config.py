"""
Settings from environment variables, or from backend/.env during local
development (see .env.example), plus the fixed limits the app enforces.
"""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL

BACKEND_DIR = Path(__file__).resolve().parent.parent
# SR-10: the certificate lives in certs/ at the project root, outside backend/, and is never committed
PROJECT_DIR = BACKEND_DIR.parent


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
    # SR-01: marks the session cookie Secure.
    # SR-10: the app is served only over HTTPS now, so there is no reason to set it false.
    cookie_secure: bool = True

    # SR-02: the Ed25519 public key that checks electoral roll signatures. The API never holds the private key.
    roll_public_key_path: Path = BACKEND_DIR / "keys" / "roll_public.pem"
    # SR-02: minimum age on the election's polling date
    min_voting_age: int = 18

    # SR-12: BALLOT_TOKEN_MINUTES is gone. A per-token expiry had to be stored as a time on the ballot
    # side; a token is now usable while its election is open and the elector is signed in (SR-04).

    # SR-07: public keys of the ballot definition delegates, as {key_id: {delegate, public_key}}.
    # The app reads only this file; the delegates' private keys never belong on the API server.
    delegate_keyring_path: Path = BACKEND_DIR / "keys" / "delegates" / "keyring.json"
    # SR-07: distinct delegates who must sign a ballot definition
    required_delegate_approvals: int = 2
    # SR-07: a definition must be activated at least this long before polls open
    min_activation_lead_hours: int = 24

    # SR-11: the AES-256 key that encrypts every stored ballot (python -m scripts.gen_ballot_key).
    # Kept beside the SR-02 keys and never committed. There is no default key and no plaintext mode.
    ballot_key_file: Path = BACKEND_DIR / "keys" / "ballot.key"

    # SR-12: where the server's log files go if its output is saved to files. The separation audit
    # scans this folder, and any *.log file in the project, for ballot identifiers.
    log_dir: Path = PROJECT_DIR / "logs"

    # SR-14: every lock wait and statement in the accept transaction stops after this many seconds,
    # with a try_again answer, so a confirmation or a refusal always comes within 10 seconds.
    # Capped at 9 so a setting can never break that promise.
    accept_timeout_seconds: int = Field(default=8, ge=1, le=9)

    # SR-13: the ballot hash chain. A batch smaller than this is sealed only with --final, so a batch
    # never narrows down which ballots arrived together.
    min_seal_batch: int = 10
    # SR-13: signed checkpoints, one JSON Lines file per election. Stands in for separate storage.
    checkpoint_dir: Path = Path("checkpoints")
    # SR-13: the server side only ever reads the public key, and only when verifying. Missing keys
    # never stop the API from starting; the private key is used by scripts/seal_ballots.py alone.
    checkpoint_public_key: Path = Path("keys/checkpoint_public.pem")
    checkpoint_private_key: Path = Path("keys/checkpoint_private.pem")

    # SR-18: the results key, used for nothing but signing released House results, so the signed
    # bytes need no domain tag and recipients can verify with standard tools. The private key is
    # read by scripts/release_results.py alone; the app only serves the public key, and starts
    # without either. Releases are folders under RELEASES_DIR (relative to backend/), never committed.
    results_private_key: Path = Path("keys/results_private.pem")
    results_public_key: Path = Path("keys/results_public.pem")
    releases_dir: Path = Path("releases")

    # SR-20: encrypted, tamper-evident backups (scripts/backup_db.py), with their own AES-256 key,
    # never the SR-11 ballot key, so a stolen backup and a stolen ballot key are separate losses.
    # Only the backup scripts read these; the API starts without them.
    backup_key_file: Path = Path("keys/backup.key")
    backups_dir: Path = Path("backups")
    # SR-20: a separate database the recovery test restores into, never the live one. It holds a
    # password, so it is a secret like POSTGRES_PASSWORD. Empty means no restore is possible.
    restore_database_url: SecretStr = SecretStr("")
    # SR-20: a restore and its checks must finish within 30 minutes
    restore_time_limit_seconds: int = Field(default=1800, gt=0)

    # SR-10: how long browsers must use HTTPS only for this host. One year by default. HSTS ignores
    # the port, so local development sets it short (.env.example) to avoid locking localhost to HTTPS.
    hsts_max_age: int = 31536000
    # SR-10: the TLS certificate and key (python -m scripts.dev_certs), relative to the project root
    tls_cert_file: Path = Path("certs/dev-cert.pem")
    tls_key_file: Path = Path("certs/dev-key.pem")
    # SR-10: the single HTTPS port for the API and the built frontend. There is no plaintext port.
    server_port: int = 8443
    # VULN-04: where the SR-10 launcher listens. This computer only by default; the container image
    # sets 0.0.0.0, and docker run publishes the port on 127.0.0.1 of the host.
    server_host: str = "127.0.0.1"

    # VULN-06: taken usernames one registration session may try at step 2 before it is ended
    max_username_attempts: int = Field(default=5, ge=1)
    # VULN-09: FastAPI's /docs, /redoc and /openapi.json, off unless switched on (development only)
    api_docs: bool = False
    # VULN-09: the Host header values the server answers; anything else gets 400. The TLS certificate
    # names localhost and 127.0.0.1. As JSON in .env: TRUSTED_HOSTS=["localhost","127.0.0.1"]
    trusted_hosts: list[str] = ["localhost", "127.0.0.1"]

    def tls_path(self, path: Path) -> Path:
        """SR-10: a certificate or key path, with relative paths taken from the project root."""
        return path if path.is_absolute() else PROJECT_DIR / path

    def backend_path(self, path: Path) -> Path:
        """SR-13: a checkpoint path or key, with relative paths taken from backend/ (beside keys/)."""
        return path if path.is_absolute() else BACKEND_DIR / path

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
