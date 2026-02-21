from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    bot_token: str
    admin_user_ids: set[int]
    alert_chat_id: int
    crowdsec_base_url: str
    crowdsec_machine_id: str
    crowdsec_machine_password: str
    crowdsec_verify_ssl: bool
    crowdsec_login_path: str
    crowdsec_decisions_path: str
    crowdsec_alerts_path: str
    crowdsec_user_agent: str
    default_ban_duration: str
    alert_poll_seconds: int
    alert_lookback_seconds: int
    alert_only_with_active_decision: bool
    log_level: str


def _require(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required env var: {name}")
    return value


def _to_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if not normalized:
        return default
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"Invalid boolean value: {value}")


def _parse_int(name: str, default: int | None = None) -> int:
    raw = os.getenv(name, "")
    if not raw.strip():
        if default is None:
            raise ConfigError(f"Missing required env var: {name}")
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"Invalid integer for {name}: {raw}") from exc


def _parse_admin_ids(raw: str) -> set[int]:
    values = set()
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        try:
            values.add(int(item))
        except ValueError as exc:
            raise ConfigError(f"Invalid Telegram user id: {item}") from exc
    if not values:
        raise ConfigError("ADMIN_USER_IDS is empty")
    return values


def load_settings() -> Settings:
    load_dotenv()

    return Settings(
        bot_token=_require("TELEGRAM_BOT_TOKEN"),
        admin_user_ids=_parse_admin_ids(_require("ADMIN_USER_IDS")),
        alert_chat_id=_parse_int("ALERT_CHAT_ID"),
        crowdsec_base_url=os.getenv("CROWDSEC_BASE_URL", "http://127.0.0.1:8080").rstrip("/"),
        crowdsec_machine_id=_require("CROWDSEC_MACHINE_ID"),
        crowdsec_machine_password=_require("CROWDSEC_MACHINE_PASSWORD"),
        crowdsec_verify_ssl=_to_bool(os.getenv("CROWDSEC_VERIFY_SSL"), default=False),
        crowdsec_login_path=os.getenv("CROWDSEC_LOGIN_PATH", "/v1/watchers/login").strip(),
        crowdsec_decisions_path=os.getenv("CROWDSEC_DECISIONS_PATH", "/v1/decisions").strip(),
        crowdsec_alerts_path=os.getenv("CROWDSEC_ALERTS_PATH", "/v1/alerts").strip(),
        crowdsec_user_agent=(
            os.getenv("CROWDSEC_USER_AGENT", "crowdsec/v1.7.6-linux").strip()
            or "crowdsec/v1.7.6-linux"
        ),
        default_ban_duration=os.getenv("DEFAULT_BAN_DURATION", "4h").strip() or "4h",
        alert_poll_seconds=max(5, _parse_int("ALERT_POLL_SECONDS", default=30)),
        alert_lookback_seconds=max(10, _parse_int("ALERT_LOOKBACK_SECONDS", default=120)),
        alert_only_with_active_decision=_to_bool(
            os.getenv("ALERT_ONLY_WITH_ACTIVE_DECISION"), default=False
        ),
        log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO",
    )
