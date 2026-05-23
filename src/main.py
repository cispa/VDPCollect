import datetime
import logging
from pathlib import Path


from Helper.Monitoring.TelegramBot import TelegramBot
from BBScrapper.startScrapper import BugBountyScrapper
from PublicListScrappers import ProjectDiscoveryScrapper, FireBountyScrapper, BugBountyTargetsScrapper
from Extractor.ExtractURLs import UrlExtractor
from Collectors.Collector import Collector

def notify(logger, telegram_bot, message: str):
    logger.info(message)
    try:
        telegram_bot.info(message)
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")

def main():
    # --------- Logging ----------
    # Initialize Telegram Bot
    telegramBot = TelegramBot()
    # Initialize the Logger:
    base_dir = Path(__file__).resolve().parent
    log_dir = (base_dir / ".." / "logs").resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    date = datetime.date.today().isoformat()
    log_file = log_dir / f"Scrapper-{date}.log"
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s: %(funcName)s(): %(message)s"
    )
    logger = logging.getLogger("scraper")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file, mode="a+", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(fh)

    notify(logger, telegramBot, "Logger initialized")


    ##### COLLECTION PHASE I
    # -------- Collecting the Information from FireBounty ---------- -> ThirdPartyBBScrapper
    logger.info("------ STARTING FIREBOUNTY SCRAPPER ------")
    telegramBot.info("------ STARTING FIREBOUNTY SCRAPPER ------")
    FBScrapper = FireBountyScrapper.FireBountyScrapper(logger)
    FBScrapper.collect()
    
    # -------- Collecting the Information ResearcherBasedCollection ---------- -> ThirdPartyBBScrapper
    telegramBot.info("------ STARTING PROJECT DISCOVERY SCRAPPER ------")
    logger.info("------ STARTING PROJECT DISCOVERY SCRAPPER ------")
    PDScrapper = ProjectDiscoveryScrapper.ProjectDiscoveryScrapper(logger)
    PDScrapper.collect()

    # -------- Collecting the Information Public Scrapping of BugBounty Targets ---------- -> ThirdPartyBBScrapper
    telegramBot.info("------ STARTING BUG-BOUNTY-TARGETS SCRAPPER ------")
    logger.info("------ STARTING BUG-BOUNTY-TARGETS SCRAPPER ------")
    BBTScrapper = BugBountyTargetsScrapper.BugBountyTargetsScrapper(logger)
    BBTScrapper.collect()

    # -------- Collecting the Information from BB/VDP Platforms ---------- -> BBScrapper
    telegramBot.info("------ STARTING BB/VDP PROVIDERS SCRAPPER ------")
    BBScrapper = BugBountyScrapper(telegramBot, logger)
    BBScrapper.start()

    ##### INTERMEDIATE STEP 
    # -------- Extract valid urls out of the collections -------- -> Extractor
    telegramBot.info("------ STARTING INTERMEDIATE URL EXTRACTION ------")
    UrlExtr = UrlExtractor(logger, telegramBot)
    UrlExtr.main()



    ##### COLLECTION PHASE II
    telegramBot.info("------ STARTING COLLECTION PHASE II ------")
    Coll = Collector(logger, telegramBot)
    Coll.main()


if __name__ == "__main__":
    main()