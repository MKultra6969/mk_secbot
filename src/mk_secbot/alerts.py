from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import UTC, datetime, timedelta
from html import escape as html_escape
from typing import Any

from aiogram import Bot

from mk_secbot.crowdsec import CrowdSecClient, CrowdSecError

logger = logging.getLogger(__name__)


class AlertWorker:
    def __init__(
        self,
        *,
        bot: Bot,
        crowdsec: CrowdSecClient,
        chat_id: int,
        poll_seconds: int,
        lookback_seconds: int,
        only_with_active_decision: bool,
    ) -> None:
        self._bot = bot
        self._crowdsec = crowdsec
        self._chat_id = chat_id
        self._poll_seconds = poll_seconds
        self._lookback_seconds = lookback_seconds
        self._only_with_active_decision = only_with_active_decision
        self._task: asyncio.Task[None] | None = None
        self._since: datetime = datetime.now(tz=UTC) - timedelta(seconds=lookback_seconds)
        self._seen = _BoundedSeen(max_items=2000)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())
            logger.info(
                "Alert worker started: chat_id=%s poll_seconds=%s",
                self._chat_id,
                self._poll_seconds,
            )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass

    async def _loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except CrowdSecError as exc:
                logger.warning("Alert polling error: %s", exc)
            except Exception:
                logger.exception("Unexpected alert polling error")
            await asyncio.sleep(self._poll_seconds)

    async def _poll_once(self) -> None:
        now = datetime.now(tz=UTC)
        alerts = await self._crowdsec.fetch_alerts(
            since=self._since,
            limit=100,
            only_with_active_decision=self._only_with_active_decision,
        )
        for alert in alerts:
            alert_key = _alert_key(alert)
            if self._seen.has(alert_key):
                continue
            self._seen.add(alert_key)
            alert_id = _read_alert_id(alert)
            source_ip = _read_source_ip(alert)
            scenario = str(alert.get("scenario") or alert.get("name") or "unknown")
            await self._bot.send_message(
                chat_id=self._chat_id,
                text=format_alert_message(alert),
            )
            logger.info(
                "Alert forwarded: id=%s ip=%s scenario=%s",
                alert_id,
                source_ip,
                scenario,
            )

        # Keep small overlap to avoid losing events between polls.
        self._since = now - timedelta(seconds=5)


def format_alert_message(alert: dict[str, Any]) -> str:
    alert_id = _escape(_read_alert_id(alert))
    scenario = _escape(str(alert.get("scenario") or alert.get("name") or "unknown"))
    source_ip = _escape(_read_source_ip(alert))
    source_scope = _escape(_read_source_scope(alert))
    country = _escape(_read_country(alert))
    as_info = _escape(_read_as_info(alert))
    reason = _escape(str(alert.get("message") or "unknown"))
    created_at = _escape(
        str(
            alert.get("created_at")
            or alert.get("createdAt")
            or alert.get("start_at")
            or "unknown"
        )
    )
    decisions = alert.get("decisions")
    decision_count = len(decisions) if isinstance(decisions, list) else 0
    events_count = _escape(
        str(alert.get("events_count") or alert.get("eventsCount") or "unknown")
    )

    lines = [
        "<b>CrowdSec alert</b>",
        f"<b>ID:</b> <code>{alert_id}</code>",
        f"<b>IP:</b> <code>{source_ip}</code>",
        f"<b>Scope:</b> <code>{source_scope}</code>",
        f"<b>Country:</b> <code>{country}</code>",
        f"<b>AS:</b> <code>{as_info}</code>",
        f"<b>Scenario:</b> <code>{scenario}</code>",
        f"<b>Message:</b> <code>{reason}</code>",
        f"<b>Created:</b> <code>{created_at}</code>",
        f"<b>Events:</b> <code>{events_count}</code>",
        f"<b>Decisions:</b> <code>{decision_count}</code>",
    ]
    return "\n".join(lines)


def _escape(value: str) -> str:
    return html_escape(value, quote=False)


def _alert_key(alert: dict[str, Any]) -> str:
    alert_id = _read_alert_id(alert)
    if alert_id != "unknown":
        return alert_id
    return f"{_read_source_ip(alert)}:{alert.get('scenario')}:{alert.get('created_at')}"


def _read_alert_id(alert: dict[str, Any]) -> str:
    for key in ("id", "ID", "uuid", "uid"):
        value = alert.get(key)
        if value is not None:
            return str(value)
    return "unknown"


def _read_source_ip(alert: dict[str, Any]) -> str:
    source = alert.get("source")
    if isinstance(source, dict):
        value = source.get("value")
        if value:
            return str(value)
    decisions = alert.get("decisions")
    if isinstance(decisions, list):
        for decision in decisions:
            if isinstance(decision, dict) and decision.get("value"):
                return str(decision["value"])
    events = alert.get("events")
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            value = event.get("source_ip") or event.get("value")
            if value:
                return str(value)
    return "unknown"


def _read_source_scope(alert: dict[str, Any]) -> str:
    source = alert.get("source")
    if isinstance(source, dict):
        scope = source.get("scope")
        if scope:
            return str(scope)
    decisions = alert.get("decisions")
    if isinstance(decisions, list):
        for decision in decisions:
            if isinstance(decision, dict) and decision.get("scope"):
                return str(decision["scope"])
    return "unknown"


def _read_country(alert: dict[str, Any]) -> str:
    source = alert.get("source")
    if isinstance(source, dict):
        for key in ("cn", "country", "country_code"):
            value = source.get(key)
            if value:
                return str(value)
    return _read_from_meta(alert, {"country", "country_code", "iso_code", "cn"})


def _read_as_info(alert: dict[str, Any]) -> str:
    source = alert.get("source")
    if isinstance(source, dict):
        as_name = source.get("as_name")
        as_number = source.get("as_number")
        if as_name and as_number:
            return f"{as_number} {as_name}"
        if as_name:
            return str(as_name)
        if as_number:
            return str(as_number)
    return _read_from_meta(alert, {"as_name", "as_num", "as_number"})


def _read_from_meta(alert: dict[str, Any], keys: set[str]) -> str:
    meta = alert.get("meta")
    if isinstance(meta, list):
        for item in meta:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or "").strip().lower()
            if key in keys and item.get("value"):
                return str(item["value"])
    return "unknown"


class _BoundedSeen:
    def __init__(self, max_items: int) -> None:
        self._max_items = max_items
        self._queue: deque[str] = deque()
        self._set: set[str] = set()

    def has(self, value: str) -> bool:
        return value in self._set

    def add(self, value: str) -> None:
        if value in self._set:
            return
        self._queue.append(value)
        self._set.add(value)
        while len(self._queue) > self._max_items:
            old = self._queue.popleft()
            self._set.discard(old)
