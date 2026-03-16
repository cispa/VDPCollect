import time
import datetime
import os
import telepot

from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[3]
load_dotenv(f'{BASE_DIR}/.env')

class TelegramBot:
    def __init__(self) -> None:
        self.bot = telepot.Bot(os.getenv('TELEGRAM_API_CODE'))
        self.chat_id = os.getenv('TELEGRAM_CHAT_ID')

    def info(self, message: str) -> None:
        print(message)
        self._send_message(message, "INFO")

    def warning(self, message: str) -> None:
        self._send_message(message, "WARNING", "i")

    def error(self, message: str) -> None:
        self._send_message(message, "ERROR", "b")

    def _send_message(self, message: str, level: str, tag: str = None) -> None:
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if tag:
                full_message = f'<b>{timestamp}</b> - <{tag}>{level}</{tag}>: {message}'
            else:
                full_message = f'{timestamp} - {level}: {message}'
            self.bot.sendMessage(self.chat_id, full_message, parse_mode='HTML')

        except telepot.exception.TelepotException as e:
            print(f"Failed to send message: {e}")
