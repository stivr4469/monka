"""Одноразовый скрипт для создания Telethon-сессии."""
import asyncio
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError, FloodWaitError

API_ID   = 34016298
API_HASH = "bee94afcfdde4330a837af8b63ddcdbb"
PHONE    = "+380988702346"
SESSION  = "/home/zastone/study/Monitoring_utechek/core/tg_session"

async def main():
    client = TelegramClient(SESSION, API_ID, API_HASH)
    await client.connect()

    if await client.is_user_authorized():
        me = await client.get_me()
        print(f"Уже авторизован как: {me.first_name} (@{me.username})")
        await client.disconnect()
        return

    try:
        # Без force_sms=True — код придёт в Telegram-приложение (надёжнее SMS)
        sent = await client.send_code_request(PHONE)
        print(f"Код отправлен через: {sent.type.__class__.__name__}")
        print("Открой Telegram-приложение — там будет сообщение с кодом.")
    except FloodWaitError as e:
        print(f"FloodWait: нужно подождать {e.seconds} секунд ({e.seconds//60} мин)")
        await client.disconnect()
        return

    code = input("\nВведи код из Telegram: ").strip()
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
