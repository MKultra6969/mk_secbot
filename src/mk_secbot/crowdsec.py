from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp


class CrowdSecError(RuntimeError):
    pass


@dataclass(frozen=True)
class CrowdSecApiConfig:
    base_url: str
    machine_id: str
    machine_password: str
    verify_ssl: bool
    login_path: str
    decisions_path: str
    alerts_path: str
    user_agent: str


def _normalize_path(path: str) -> str:
    if not path.startswith("/"):
        return f"/{path}"
    return path


def _parse_jwt_exp(token: str) -> datetime | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    exp = data.get("exp")
    if isinstance(exp, int):
        return datetime.fromtimestamp(exp, tz=UTC)
    return None


class CrowdSecClient:
    def __init__(self, config: CrowdSecApiConfig) -> None:
        self._config = config
        self._session = aiohttp.ClientSession(
            headers={"User-Agent": config.user_agent},
            timeout=aiohttp.ClientTimeout(total=20),
        )
        self._token: str | None = None
        self._token_exp_at: datetime | None = None

    async def close(self) -> None:
        await self._session.close()

    def _url(self, path: str) -> str:
        return f"{self._config.base_url}{_normalize_path(path)}"

    def _token_is_fresh(self) -> bool:
        if not self._token:
            return False
        if not self._token_exp_at:
            return True
        return datetime.now(tz=UTC) < (self._token_exp_at - timedelta(minutes=1))

    async def _login(self) -> None:
        payload = {
            "machine_id": self._config.machine_id,
            "password": self._config.machine_password,
        }
        login_url = self._url(self._config.login_path)
        try:
            async with self._session.post(
                login_url,
                json=payload,
                ssl=self._config.verify_ssl,
            ) as response:
                data = await _read_json_or_text(response)
                if response.status >= 400:
                    raise CrowdSecError(
                        f"CrowdSec login failed: HTTP {response.status} - {data}"
                    )
        except asyncio.TimeoutError as exc:
            raise CrowdSecError(f"CrowdSec login timeout: {login_url}") from exc
        except aiohttp.ClientError as exc:
            raise CrowdSecError(f"CrowdSec login network error: {login_url} - {exc}") from exc
        if not isinstance(data, dict) or not data.get("token"):
            raise CrowdSecError(f"CrowdSec login returned unexpected payload: {data}")
        self._token = str(data["token"])
        self._token_exp_at = _parse_jwt_exp(self._token)

    async def _auth_headers(self) -> dict[str, str]:
        if not self._token_is_fresh():
            await self._login()
        if not self._token:
            raise CrowdSecError("CrowdSec auth token is empty after login")
        return {"Authorization": f"Bearer {self._token}"}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        auth: bool = True,
        retry_on_401: bool = True,
    ) -> Any:
        headers: dict[str, str] = {}
        if auth:
            headers.update(await self._auth_headers())

        request_url = self._url(path)
        try:
            async with self._session.request(
                method,
                request_url,
                params=params,
                json=json_body,
                headers=headers,
                ssl=self._config.verify_ssl,
            ) as response:
                data = await _read_json_or_text(response)
        except asyncio.TimeoutError as exc:
            raise CrowdSecError(f"CrowdSec request timeout: {method} {request_url}") from exc
        except aiohttp.ClientError as exc:
            raise CrowdSecError(
                f"CrowdSec request network error: {method} {request_url} - {exc}"
            ) from exc

        if response.status == 401 and auth and retry_on_401:
            self._token = None
            self._token_exp_at = None
            return await self._request(
                method,
                path,
                params=params,
                json_body=json_body,
                auth=auth,
                retry_on_401=False,
            )

        if response.status >= 400:
            raise CrowdSecError(
                f"CrowdSec request failed: {method} {path} "
                f"(HTTP {response.status}) - {data}"
            )
        return data

    async def ping(self) -> None:
        await self._auth_headers()

    async def ban_ip(self, ip: str, duration: str, reason: str | None = None) -> None:
        decision = {
            "scope": "Ip",
            "value": ip,
            "type": "ban",
            "duration": duration,
            "origin": "cscli",
            "scenario": reason or "manual/by-telegram-bot",
            "simulated": False,
        }
        post_not_allowed = False
        try:
            await self._request(
                "POST",
                self._config.decisions_path,
                json_body=[decision],
            )
            return
        except CrowdSecError as exc:
            if "(HTTP 405)" in str(exc):
                post_not_allowed = True
            elif "(HTTP 400)" not in str(exc):
                raise
        if not post_not_allowed:
            try:
                await self._request(
                    "POST",
                    self._config.decisions_path,
                    json_body=decision,
                )
                return
            except CrowdSecError as exc:
                if "(HTTP 405)" not in str(exc):
                    raise
        try:
            await self._ban_ip_via_signals(ip=ip, duration=duration, reason=reason)
            return
        except CrowdSecError as signals_exc:
            try:
                await self._ban_ip_via_alerts(ip=ip, duration=duration, reason=reason)
                return
            except CrowdSecError as alerts_exc:
                raise CrowdSecError(
                    "CrowdSec ban failed: POST /decisions is not allowed on this LAPI and "
                    f"fallbacks also failed (signals: {signals_exc}; alerts: {alerts_exc})"
                ) from alerts_exc

    async def unban_ip(self, ip: str) -> None:
        try:
            await self._request(
                "DELETE",
                self._config.decisions_path,
                params={"ip": ip},
            )
        except CrowdSecError as exc:
            if "(HTTP 400)" not in str(exc):
                raise
            await self._request(
                "DELETE",
                self._config.decisions_path,
                params={"value": ip},
            )

    async def fetch_alerts(
        self,
        *,
        since: datetime | None = None,
        limit: int = 100,
        only_with_active_decision: bool = False,
    ) -> list[dict[str, Any]]:
        params_base: dict[str, Any] = {"limit": limit}
        if only_with_active_decision:
            params_base["has_active_decision"] = "true"

        payload: Any
        if since is None:
            payload = await self._request(
                "GET",
                self._config.alerts_path,
                params=params_base,
            )
        else:
            since_utc = since.astimezone(UTC)
            params_iso = dict(params_base)
            params_iso["since"] = since_utc.isoformat().replace("+00:00", "Z")
            try:
                payload = await self._request(
                    "GET",
                    self._config.alerts_path,
                    params=params_iso,
                )
            except CrowdSecError as exc:
                # Some CrowdSec versions expect `since` as Go duration (e.g. 120s),
                # while others accept RFC3339 timestamp.
                if not _looks_like_since_duration_error(exc):
                    raise
                seconds = max(1, int((datetime.now(tz=UTC) - since_utc).total_seconds()))
                params_duration = dict(params_base)
                params_duration["since"] = f"{seconds}s"
                payload = await self._request(
                    "GET",
                    self._config.alerts_path,
                    params=params_duration,
                )

        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        if isinstance(payload, dict):
            for key in ("alerts", "items", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [x for x in value if isinstance(x, dict)]
        return []

    async def _ban_ip_via_signals(self, ip: str, duration: str, reason: str | None) -> None:
        now = datetime.now(tz=UTC)
        stop_at = now + (_duration_to_timedelta(duration) or timedelta(hours=1))
        scenario = reason or "manual/by-telegram-bot"
        signal = {
            "context": [{"key": "source_ip", "value": ip}],
            "created_at": _to_rfc3339(now),
            "decisions": [
                {
                    "id": 0,
                    "duration": duration,
                    "origin": "cscli",
                    "scenario": scenario,
                    "scope": "Ip",
                    "type": "ban",
                    "value": ip,
                }
            ],
            "machine_id": self._config.machine_id,
            "message": f"manual ban via telegram bot: {ip}",
            "scenario": scenario,
            "scenario_hash": "manual/telegram-bot",
            "scenario_version": "1.0",
            "source": {"scope": "Ip", "value": ip},
            "start_at": _to_rfc3339(now),
            "stop_at": _to_rfc3339(stop_at),
        }
        await self._request(
            "POST",
            "/v1/signals",
            json_body=[signal],
        )

    async def _ban_ip_via_alerts(self, ip: str, duration: str, reason: str | None) -> None:
        now = datetime.now(tz=UTC)
        stop_at = now + (_duration_to_timedelta(duration) or timedelta(hours=1))
        scenario = reason or "manual/by-telegram-bot"
        alert = {
            "capacity": 1,
            "decisions": [
                {
                    "duration": duration,
                    "origin": "cscli",
                    "scenario": scenario,
                    "scope": "Ip",
                    "type": "ban",
                    "value": ip,
                }
            ],
            "events": [
                {
                    "meta": [
                        {"key": "source_ip", "value": ip},
                        {"key": "service", "value": "telegram-bot"},
                    ],
                    "timestamp": _to_rfc3339(now),
                }
            ],
            "events_count": 1,
            "labels": [],
            "leakspeed": "10s",
            "message": f"manual ban via telegram bot: {ip}",
            "meta": [{"key": "source_ip", "value": ip}],
            "remediation": True,
            "scenario": scenario,
            "scenario_hash": "manual/telegram-bot",
            "scenario_version": "1.0",
            "simulated": False,
            "source": {"scope": "Ip", "value": ip},
            "start_at": _to_rfc3339(now),
            "stop_at": _to_rfc3339(stop_at),
        }
        await self._request(
            "POST",
            self._config.alerts_path,
            json_body=[alert],
        )


async def _read_json_or_text(response: aiohttp.ClientResponse) -> Any:
    text = await response.text()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _looks_like_since_duration_error(exc: CrowdSecError) -> bool:
    text = str(exc).lower()
    return "parsing duration" in text or "misplaced negative sign in duration" in text


def _to_rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


_DURATION_PART_RE = re.compile(r"(\d+)([smhdwMy])")


def _duration_to_timedelta(value: str) -> timedelta | None:
    if not value:
        return None
    total = timedelta(0)
    pos = 0
    for match in _DURATION_PART_RE.finditer(value):
        if match.start() != pos:
            return None
        pos = match.end()
        amount = int(match.group(1))
        unit = match.group(2)
        if unit == "s":
            total += timedelta(seconds=amount)
        elif unit == "m":
            total += timedelta(minutes=amount)
        elif unit == "h":
            total += timedelta(hours=amount)
        elif unit == "d":
            total += timedelta(days=amount)
        elif unit == "w":
            total += timedelta(weeks=amount)
        elif unit == "M":
            total += timedelta(days=30 * amount)
        elif unit == "y":
            total += timedelta(days=365 * amount)
    if pos != len(value):
        return None
    return total if total > timedelta(0) else None
