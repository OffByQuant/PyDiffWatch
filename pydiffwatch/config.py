import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path


@dataclass(frozen=True)
class ReviewerConfig:
    # provider: "openai" (any OpenAI-compatible endpoint — OpenAI, Ollama, llama.cpp, llama-swap, vLLM,
    # LM Studio, OpenRouter, ...) | "anthropic" (native SDK).
    provider: str = "openai"
    # Set to your endpoint. Ollama: http://localhost:11434/v1 ; llama.cpp: http://localhost:8080/v1 ;
    # OpenAI: https://api.openai.com/v1 . Unused for provider="anthropic".
    base_url: str = "http://localhost:8000/v1"
    model: str = "qwen-singleshot"
    # NAME of the env var holding the API key (e.g. "OPENAI_API_KEY"); NEVER the key itself. None = no auth.
    api_key_env: str | None = None
    # "json_schema" (strict server-side, preferred) | "json_object" (loose JSON) | "none" (prompt-only).
    # The client always validates the parsed verdict against REVIEW_SCHEMA regardless of mode.
    structured_output: str = "json_schema"
    escalation_model: str | None = None
    timeout: float = 120.0
    max_input_chars: int = 200_000
    max_output_tokens: int = 8192
    opus_escalation_confidence: float = 0.6


@dataclass(frozen=True)
class Config:
    db_path: Path = Path(".diffwatch/diffwatch.sqlite")
    cache_dir: Path = Path(".diffwatch/artifact_cache")
    lock_path: Path = Path(".diffwatch/diffwatch.lock")
    # containment caps (ported verbatim from main DiffWatch)
    max_download_bytes: int = 50 * 1024 * 1024
    max_members: int = 2000
    max_member_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_source_file_bytes: int = 1 * 1024 * 1024
    max_name_bytes: int = 4096
    max_foreign_files: int = 25
    dep_brandnew_days: int = 30
    max_dep_lookups: int = 10
    max_decompressed_bytes: int = 120 * 1024 * 1024
    fetch_timeout_s: float = 30.0
    max_releases_per_run: int = 2000
    fetch_concurrency: int = 4
    new_package_policy: str = "surface"   # "surface" | "skip" | "full"
    threshold_t: float = 40.0             # baseline default; production-tuned value held back in main
    pypi_base: str = "https://pypi.org"
    webhook_url: str | None = None
    evidence_max_chars: int = 200_000
    reviewer_enabled: bool = True
    rules_dir: Path = Path("rules/community")
    reviewer: ReviewerConfig = field(default_factory=ReviewerConfig)


def load_config(path) -> Config:
    """Load config from a TOML file, falling back to defaults for a missing file or absent keys.
    Unknown keys are ignored. API keys are NEVER read from the file — only the env-var name is."""
    path = Path(path)
    if not path.exists():
        return Config()
    raw = tomllib.loads(path.read_text())
    rv = raw.pop("reviewer", {})
    default_rv = ReviewerConfig()
    reviewer = replace(default_rv, **{k: v for k, v in rv.items() if hasattr(default_rv, k)})
    default = Config()
    top = {k: v for k, v in raw.items() if hasattr(default, k) and k != "reviewer"}
    # Path-typed fields arrive as strings from TOML; coerce.
    for pk in ("db_path", "cache_dir", "lock_path", "rules_dir"):
        if pk in top:
            top[pk] = Path(top[pk])
    return replace(default, reviewer=reviewer, **top)
