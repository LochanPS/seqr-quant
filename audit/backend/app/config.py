from functools import lru_cache

from pydantic_settings import BaseSettings

_DEFAULT_SECRET = "dev-secret-change-in-production"


class Settings(BaseSettings):
    DEPLOYMENT_MODE: str = "onprem"
    SECRET_KEY: str = _DEFAULT_SECRET
    ENVIRONMENT: str = "development"
    FRONTEND_URL: str = "http://localhost:3000"
    DATABASE_URL: str = "sqlite+aiosqlite:///./seqr.db"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    REDIS_URL: str = "redis://localhost:6379/0"
    USE_FAKE_REDIS: bool = True
    # Run scans inline (no separate Celery worker) even with a real Redis broker.
    # Lets a single web service host the whole app on free tiers; scans block the
    # request until done. Set False once a dedicated worker process is deployed.
    CELERY_ALWAYS_EAGER: bool = False
    # Fairness cap: max scans one org may have in flight on the worker pool at once.
    # A tenant that queues more than this has the excess re-queued (Celery retry) so
    # it can't occupy every worker slot and starve other tenants. 0 = unlimited.
    # Enforced only with a real broker (ignored when eager/fakeredis). Global
    # throughput is bounded separately by the worker's --concurrency flag.
    MAX_CONCURRENT_SCANS_PER_ORG: int = 3
    # Safety TTL (s) on the per-org in-flight counter: a worker that dies mid-scan
    # without releasing its slot can wedge an org for at most this long.
    SCAN_ORG_INFLIGHT_TTL: int = 900
    # Seconds a capped task waits before Celery re-queues it (backoff jitter added).
    SCAN_RETRY_COUNTDOWN: int = 5
    LICENSE_KEY: str = ""
    # PEM public key for license validation; set after running scripts/generate_license.py
    LICENSE_PUBLIC_KEY: str = ""
    # Platform operators (founder/staff) — comma-separated emails with admin-console access.
    OPERATOR_EMAILS: str = ""
    # Allow the demo template switcher (/migration/demo/reseed) on a SaaS deployment. OFF by
    # default so production SaaS never lets a reseed wipe/reload org data. Set true ONLY on a
    # dedicated demo instance so the Posture template switcher works there.
    ALLOW_DEMO_RESEED: bool = False
    # Seed the demo org (demo@seqrlabs.com + banking template) on startup if the DB is empty.
    # For shell-less hosts (Render free). Idempotent; safe to leave on. Demo instances only.
    SEED_DEMO_ON_BOOT: bool = False
    # Accept PR crypto findings pushed from `seqr ci` (POST /api/v1/ci/findings) into the
    # org's dashboard/CBOM. OFF by default (feature-flagged); enable per deployment once the
    # dashboard surfaces CI reports. Read + write are always org-scoped and authenticated.
    CI_INGEST_ENABLED: bool = False

    # -- Discovery agent plane (PRD 15) ---------------------------------------
    # Accept internal crypto-posture observations pushed by an on-prem discovery agent
    # (POST /api/v1/agent/observations). The agent authenticates with an `agent`-scoped
    # sq_live_ key and its observations enter the spine graph as source=discovery_agent
    # (precedence 40, inside beats outside). OFF by default (feature-flagged) so a
    # deployment opts in before accepting agent uploads. Credential issue/list/revoke and
    # every read/write are org-scoped and authenticated regardless of this flag.
    AGENT_INGEST_ENABLED: bool = False

    # -- Hosted GitHub App (PRD 07, CI-4) -------------------------------------
    # Zero-config PR scanning: GitHub posts a webhook, a worker scans the changed lines
    # and posts an inline review + commit status. OFF by default and only accepts webhooks
    # once configured. Never registers/deploys anything on its own.
    GITHUB_APP_ENABLED: bool = False
    GITHUB_APP_ID: str = ""
    # App private key (PEM). Env vars flatten newlines — literal "\n" sequences are
    # restored to real newlines at load (see github_app.client).
    GITHUB_APP_PRIVATE_KEY: str = ""
    # Webhook secret (openssl rand -hex 32) — the HMAC-SHA256 key the receiver validates.
    GITHUB_WEBHOOK_SECRET: str = ""
    GITHUB_API_URL: str = "https://api.github.com"
    # Commit-status gating threshold: a finding at this severity or above marks the status
    # `failure`, else `success`. Empty = advisory (never fail), honouring exit-0-by-default.
    GITHUB_APP_FAIL_ON: str = ""
    # Persist each PR scan as a CIReport (reuses the CI-2 dashboard model) when true.
    GITHUB_APP_PERSIST_REPORTS: bool = True

    # -- Enterprise SSO: OIDC (PRD / A5) --------------------------------------
    # Master switch for the SSO login/callback flow. OFF by default; an org must also
    # configure + enable its own OIDCProvider. Provider CRUD is always available to org
    # admins so config can be staged before the flow is switched on.
    SSO_ENABLED: bool = False
    # Public base URL of THIS backend, used to build the OIDC redirect_uri
    # ({base}/api/v1/sso/oidc/callback). Empty = derive from the incoming request
    # (fine behind a correctly-configured proxy; set explicitly to be safe).
    OIDC_REDIRECT_BASE: str = ""

    # -- Enterprise SSO: SAML 2.0 (PRD / A5) ----------------------------------
    # Master switch for the SAML login/ACS/SLO flow. OFF by default; an org must also
    # configure + enable its own SAMLProvider. Provider CRUD is always available to org
    # admins so config (metadata, ACS URL) can be staged before the flow is switched on.
    SAML_ENABLED: bool = False
    # Public base URL of THIS backend, used to build the SP ACS URL, EntityID and metadata
    # ({base}/api/v1/saml/acs). Empty = derive from the incoming request (fine behind a
    # correctly-configured proxy; set explicitly to be safe). Mirrors OIDC_REDIRECT_BASE.
    SAML_ACS_BASE: str = ""

    @property
    def operator_email_set(self) -> set[str]:
        return {e.strip().lower() for e in self.OPERATOR_EMAILS.split(",") if e.strip()}

    @property
    def async_database_url(self) -> str:
        """URL for the async engine. Managed Postgres (Render/Neon) injects a bare
        ``postgresql://`` URL; the async engine needs the asyncpg driver."""
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    @property
    def sync_database_url(self) -> str:
        """URL for the sync engine (Celery tasks) — strip the async driver prefix."""
        return self.async_database_url.replace("+asyncpg", "").replace("+aiosqlite", "")

    class Config:
        env_file = ".env"

    def validate_production(self) -> None:
        """Refuse to run a production deployment with insecure dev defaults.

        A default SECRET_KEY means every JWT is forgeable from a value that is
        public in the source tree — full auth bypass. fakeredis / sqlite in
        production silently lose data and break the WS pub/sub channel. Fail
        loud at boot rather than ship a quietly-broken, insecure service.
        """
        if self.ENVIRONMENT != "production":
            return
        errors = []
        if self.SECRET_KEY == _DEFAULT_SECRET or len(self.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be set to a strong (>=32 char) random value")
        if self.USE_FAKE_REDIS:
            errors.append("USE_FAKE_REDIS must be False (real Redis required for Celery + WS)")
        if self.DATABASE_URL.startswith("sqlite"):
            errors.append("DATABASE_URL must be PostgreSQL, not SQLite")
        if self.FRONTEND_URL.startswith("http://localhost"):
            errors.append("FRONTEND_URL must be the real production origin (CORS)")
        if errors:
            raise RuntimeError(
                "Refusing to start in production with insecure configuration:\n  - "
                + "\n  - ".join(errors)
            )


@lru_cache()
def get_settings() -> Settings:
    s = Settings()
    s.validate_production()
    return s


settings = get_settings()
