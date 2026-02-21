from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties

from mk_secbot.alerts import AlertWorker
from mk_secbot.bot_app import AppContext, build_router
from mk_secbot.config import ConfigError, load_settings
from mk_secbot.crowdsec import CrowdSecApiConfig, CrowdSecClient


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


async def run() -> None:
    settings = load_settings()
    configure_logging(settings.log_level)

    crowdsec = CrowdSecClient(
        CrowdSecApiConfig(
            base_url=settings.crowdsec_base_url,
            machine_id=settings.crowdsec_machine_id,
            machine_password=settings.crowdsec_machine_password,
            verify_ssl=settings.crowdsec_verify_ssl,
            login_path=settings.crowdsec_login_path,
            decisions_path=settings.crowdsec_decisions_path,
            alerts_path=settings.crowdsec_alerts_path,
            user_agent=settings.crowdsec_user_agent,
        )
    )

    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode="HTML"),
    )
    dispatcher = Dispatcher()
    dispatcher.include_router(build_router(AppContext(settings=settings, crowdsec=crowdsec)))

    alert_worker = AlertWorker(
        bot=bot,
        crowdsec=crowdsec,
        chat_id=settings.alert_chat_id,
        poll_seconds=settings.alert_poll_seconds,
        lookback_seconds=settings.alert_lookback_seconds,
        only_with_active_decision=settings.alert_only_with_active_decision,
    )
    alert_worker.start()

    try:
        await dispatcher.start_polling(
            bot,
            allowed_updates=dispatcher.resolve_used_update_types(),
        )
    finally:
        await alert_worker.stop()
        await crowdsec.close()
        await bot.session.close()


def main() -> None:
    try:
        asyncio.run(run())
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
