from __future__ import annotations

from collections.abc import Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, User


class AdminOnlyMiddleware(BaseMiddleware):
    def __init__(self, admin_user_ids: set[int]) -> None:
        self._admin_user_ids = admin_user_ids

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict], Awaitable[object]],
        event: TelegramObject,
        data: dict,
    ) -> object | None:
        user: User | None = data.get("event_from_user")
        if user is None:
            return None
        if user.id not in self._admin_user_ids:
            # Strict ignore for non-admin users.
            return None
        return await handler(event, data)

