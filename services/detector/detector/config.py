from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSWARDEN_", env_file=".env", extra="ignore")

    # Elasticsearch (read-only)
    es_url: str = "https://localhost:9200"
    es_user: str = "opswarden-reader"
    es_password: str = ""
    es_ca_cert: str | None = None          # path; None => don't verify (self-signed lab)

    # Detection thresholds
    brute_force_threshold: int = 20        # failed logins from one IP in the window
    window_minutes: int = 10
    dormant_days: int = 90                 # no successful login in this many days => dormant

    # Where to send events (None => just print them)
    api_url: str | None = None
    api_token: str = ""        # presented as X-OpsWarden-Token when posting events
    poll_seconds: int = 30
