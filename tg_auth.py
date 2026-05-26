"""Одноразовый скрипт для создания Telethon-сессии."""
import asyncio
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError

API_ID   = 34016298
API_HASH = "bee94afcfdde4330a837af8b63ddcdbb"
PHONE    = "+380988702346"
SESSION  = "/home/zastone/study/Monitoring_utechek/core/tg_session"

async def main():
    client = TelegramClient(SESSION, API_ID, API_HASH)
    await client.connect()

    if not await client.is_user_authorized():
        await client.send_code_request(PHONE, force_sms=True)
        code = input("Введи код из Telegram: ").strip()
        try:
            await client.sign_in(PHONE, code)
        except SessionPasswordNeededError:
            pwd = input("Введи пароль 2FA: ").strip()
            await client.sign_in(password=pwd)

    me = await client.get_me()
    print(f"\nАвторизован как: {me.first_name} (@{me.username})")
    print(f"Сессия сохранена: {SESSION}.session")
    await client.disconnect()

asyncio.run(main())
