import datetime
from pathlib import Path

from BBScrapper.BugCrowd.BugCrowdScrapper import BugCrowdScrapper
from BBScrapper.HackerOne.HackerOneScrapper import HackerOneScrapper
from BBScrapper.Huoxian.HuoxianScrapper import HuoxianScrapper
from BBScrapper.Intigriti.IntigritiScrapper import IntigritiScrapper
from BBScrapper.YesWeHack.YesWeHackScrapper import YesWeHackScrapper
from Helper.Monitoring.TelegramBot import TelegramBot


class BugBountyScrapper:
    def __init__(self, telegramBot: TelegramBot, log) -> None:
        self.teleBot = telegramBot
        self.logger = log

    def _get_log_file(self) -> Path:
        """Resolve scraper log file path based on project root."""
        today = datetime.date.today()
        base_dir = Path(__file__).resolve().parents[2]
        logs_dir = base_dir / "logs"
        return logs_dir / f"Scrapper-{today}.log"

    def _summarize_errors(self):
        """Count ERROR lines in scraper log and send summary via Telegram."""
        log_file = self._get_log_file()

        if not log_file.exists():
            self.teleBot.error(f"Log file not found: {log_file}")
            return

        error_count = 0
        try:
            with log_file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if " ERROR: " in line:
                        error_count += 1
        except Exception as e:
            self.teleBot.error(f"Failed to read log file {log_file}: {e}")
            return

        self.teleBot.info(
            f"The file '{log_file}' contains {error_count} lines with the string ' ERROR: '"
        )

    def start(self):
        # Instantiate scrapers
        bugcrowd_scraper = BugCrowdScrapper(self.logger, self.teleBot)
        hackerone_scraper = HackerOneScrapper(self.logger, self.teleBot)
        yeswehack_scraper = YesWeHackScrapper(self.logger, self.teleBot)
        intigriti_scraper = IntigritiScrapper(self.logger, self.teleBot)
        # Deprecated - We could not fully register without a local phone number
        # huoxian_scraper = HuoxianScrapper(self.logger, self.teleBot)

        self.teleBot.info("---- STARTING SCRAPER ----")

        # Run enabled scrapers
        yeswehack_scraper.run()
        intigriti_scraper.run()
        bugcrowd_scraper.run()
        hackerone_scraper.run()
        
        # Deprecated - We could not fully register without a local phone number
        # huoxian_scraper.run()

        # Summarize errors from log
        self._summarize_errors()

        self.teleBot.info("---- SCRAPER FINISHED ----")