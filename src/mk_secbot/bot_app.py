from __future__ import annotations

import ipaddress
import logging
import re
import shlex
from dataclasses import dataclass
from html import escape as html_escape

from aiogram import Router
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import Message

from mk_secbot.access import AdminOnlyMiddleware
from mk_secbot.alerts import format_alert_message
from mk_secbot.config import Settings
from mk_secbot.crowdsec import CrowdSecClient, CrowdSecError

logger = logging.getLogger(__name__)

_DURATION_RE = re.compile(r"^\d+[smhdwMy](?:\d+[smhdwMy])*$")


@dataclass(frozen=True)
class AppContext:
    settings: Settings
    crowdsec: CrowdSecClient


def build_router(ctx: AppContext) -> Router:
    router = Router()
    admin_middleware = AdminOnlyMiddleware(ctx.settings.admin_user_ids)
    router.message.middleware(admin_middleware)
    router.edited_message.middleware(admin_middleware)
    router.callback_query.middleware(admin_middleware)

    @router.message(CommandStart())
    async def start_handler(message: Message) -> None:
        await message.answer(_help_text())

    @router.message(Command("help"))
    async def help_handler(message: Message) -> None:
        await message.answer(_help_text())

    @router.message(Command("status"))
    async def status_handler(message: Message) -> None:
        try:
            await ctx.crowdsec.ping()
            await message.answer("<b>CrowdSec API:</b> <code>ok</code>")
        except Exception as exc:
            err = _format_exception(exc)
            logger.warning("Status check failed: %s", err)
            await message.answer(
                "<b>CrowdSec API error:</b>\n"
                f"<code>{_escape(err)}</code>"
            )

    @router.message(Command("ban"))
    async def ban_handler(message: Message, command: CommandObject) -> None:
        try:
            ip, duration, reason = parse_ban_command(
                command.args or "",
                default_duration=ctx.settings.default_ban_duration,
            )
        except ValueError as exc:
            await message.answer(
                f"<b>{_escape(str(exc))}</b>\n"
                "Usage: <code>/ban &lt;ip&gt; [duration] [reason]</code>"
            )
            return

        actor_id = message.from_user.id if message.from_user else "unknown"
        logger.info("Ban request: ip=%s duration=%s by=%s", ip, duration, actor_id)
        try:
            await ctx.crowdsec.ban_ip(ip=ip, duration=duration, reason=reason)
        except CrowdSecError as exc:
            logger.warning("Ban failed: %s", exc)
            await message.answer(
                "<b>Ban failed</b>\n"
                f"<code>{_escape(str(exc))}</code>"
            )
            return

        logger.info("Ban created: ip=%s duration=%s", ip, duration)
        await message.answer(
            "<b>Ban created</b>\n"
            f"<b>IP:</b> <code>{_escape(ip)}</code>\n"
            f"<b>Duration:</b> <code>{_escape(duration)}</code>\n"
            f"<b>Reason:</b> <code>{_escape(reason or 'manual')}</code>"
        )

    @router.message(Command("unban"))
    async def unban_handler(message: Message, command: CommandObject) -> None:
        try:
            ip = parse_unban_command(command.args or "")
        except ValueError as exc:
            await message.answer(
                f"<b>{_escape(str(exc))}</b>\n"
                "Usage: <code>/unban &lt;ip&gt;</code>"
            )
            return

        actor_id = message.from_user.id if message.from_user else "unknown"
        logger.info("Unban request: ip=%s by=%s", ip, actor_id)
        try:
            await ctx.crowdsec.unban_ip(ip=ip)
        except CrowdSecError as exc:
            logger.warning("Unban failed: %s", exc)
            await message.answer(
                "<b>Unban failed</b>\n"
                f"<code>{_escape(str(exc))}</code>"
            )
            return

        logger.info("Unban completed: ip=%s", ip)
        await message.answer(
            "<b>Unban completed</b>\n"
            f"<b>IP:</b> <code>{_escape(ip)}</code>"
        )

    @router.message(Command("alerts"))
    async def alerts_handler(message: Message, command: CommandObject) -> None:
        try:
            count = _parse_alerts_count(command.args or "")
        except ValueError as exc:
            await message.answer(
                f"<b>{_escape(str(exc))}</b>\n"
                "Usage: <code>/alerts [count]</code>"
            )
            return

        actor_id = message.from_user.id if message.from_user else "unknown"
        logger.info("Alerts list request: count=%s by=%s", count, actor_id)
        try:
            alerts = await ctx.crowdsec.fetch_alerts(
                since=None,
                limit=count,
                only_with_active_decision=False,
            )
        except CrowdSecError as exc:
            logger.warning("Alerts list failed: %s", exc)
            await message.answer(
                "<b>Alerts fetch failed</b>\n"
                f"<code>{_escape(str(exc))}</code>"
            )
            return

        if not alerts:
            await message.answer("<b>No alerts found</b>")
            return

        rendered_blocks = []
        for idx, alert in enumerate(alerts[:count], start=1):
            rendered_blocks.append(f"<b>#{idx}</b>\n{format_alert_message(alert)}")

        header = f"<b>Recent CrowdSec alerts:</b> <code>{len(rendered_blocks)}</code>"
        for chunk in _split_html_chunks(header, rendered_blocks):
            await message.answer(chunk)
        logger.info("Alerts list delivered: count=%s", len(rendered_blocks))

    return router


def parse_ban_command(args: str, default_duration: str) -> tuple[str, str, str | None]:
    parts = shlex.split(args)
    if not parts:
        raise ValueError("IP is required")
    ip = _validate_ip(parts[0])
    if len(parts) == 1:
        return ip, default_duration, None

    if _looks_like_duration(parts[1]):
        duration = parts[1]
        reason = " ".join(parts[2:]).strip() or None
    else:
        duration = default_duration
        reason = " ".join(parts[1:]).strip() or None
    return ip, duration, reason


def parse_unban_command(args: str) -> str:
    parts = shlex.split(args)
    if len(parts) != 1:
        raise ValueError("Only one IP is expected")
    return _validate_ip(parts[0])


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def _looks_like_duration(value: str) -> bool:
    return bool(_DURATION_RE.match(value))


def _help_text() -> str:
    return (
        "<b>Available commands</b>\n"
        "<code>/status</code> - check CrowdSec connection\n"
        "<code>/ban &lt;ip&gt; [duration] [reason]</code> - create ban decision\n"
        "<code>/unban &lt;ip&gt;</code> - remove ban decision\n"
        "<code>/alerts [count]</code> - show recent alerts (1..15)\n"
        "<code>/help</code> - show this message"
    )


def _format_exception(exc: Exception) -> str:
    text = str(exc).strip()
    if text:
        return text
    return exc.__class__.__name__


def _escape(value: str) -> str:
    return html_escape(value, quote=False)


def _parse_alerts_count(args: str) -> int:
    default_count = 5
    if not args.strip():
        return default_count
    parts = shlex.split(args)
    if len(parts) != 1:
        raise ValueError("Only one numeric argument is allowed")
    try:
        value = int(parts[0])
    except ValueError as exc:
        raise ValueError("Count must be an integer") from exc
    if value < 1 or value > 15:
        raise ValueError("Count must be between 1 and 15")
    return value


def _split_html_chunks(header: str, blocks: list[str], limit: int = 3800) -> list[str]:
    chunks: list[str] = []
    current = header
    for block in blocks:
        candidate = f"{current}\n\n{block}"
        if len(candidate) > limit:
            chunks.append(current)
            current = block
            continue
        current = candidate
    chunks.append(current)
    return chunks
