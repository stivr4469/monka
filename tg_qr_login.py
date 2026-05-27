"""QR-код авторизация Telethon — запускать интерактивно."""
import asyncio
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError

API_ID   = 34016298
API_HASH = "bee94afcfdde4330a837af8b63ddcdbb"
SESSION  = "/home/zastone/study/Monitoring_utechek/core/tg_session"

def print_qr(url: str):
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        print(f"\nQR URL: {url}")
        print("Открой в браузере: https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=" + url)

async def main():
    client = TelegramClient(SESSION, API_ID, API_HASH)
    await client.connect()

    if await client.is_user_authorized():
        me = await client.get_me()
        print(f"Уже авторизован: {me.first_name} (@{me.username})")
        await client.disconnect()
        return

    print("Генерирую QR-код для входа...\n")
    qr_login = await client.qr_login()
    print_qr(qr_login.url)
    print("\nКак сканировать:")
    print("  Android: Настройки → Устройства → Подключить устройство")
    print("  iPhone:  Настройки → Устройства → Подключить устройство")
    print("  Web:     ≡ → Настройки → Устройства → Подключить устройство\n")
    print("Жду сканирования (60 сек)...")

    try:
        await asyncio.wait_for(qr_login.wait(), timeout=60)
    except asyncio.TimeoutError:
        print("Время вышло. Запусти скрипт снова.")
        await client.disconnect()
        return
    except SessionPasswordNeededError:
        pwd = input("Введи пароль 2FA: ").strip()
        await client.sign_in(password=pwd)

    me = await client.get_me()
    print(f"\nАвторизован: {me.first_name} (@{me.username})")
    print(f"Сессия: {SESSION}.session")
    await client.disconnect()

asyncio.run(main())
