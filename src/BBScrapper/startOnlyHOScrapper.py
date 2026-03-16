import logging
import datetime

from BugCrowd.BugCrowdScrapper import BugCrowdScrapper
from HackerOne.HackerOneScrapper import HackerOneScrapper
from unittest.mock import MagicMock
from Huoxian.HuoxianScrapper import HuoxianScrapper
from Intigriti.IntigritiScrapper import IntigritiScrapper
from TelegramBot.TelegramBot import TelegramBot
from YesWeHack.YesWeHackScrapper import YesWeHackScrapper

if __name__ == '__main__':
    # Initialize Telegram Bot
    # disabled for now
    # teleBot = TelegramBot()
    teleBot = MagicMock()

    # Initialize the Logger:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(funcName)s(): %(message)s')
    logger = logging.getLogger(__name__)

    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(funcName)s(): %(message)s')

    # add logger file
    date = str(datetime.date.today())
    fh = logging.FileHandler(f'/Users/Redacted_authorRedacted_author/Documents/MasterThesis/code/Scrapper/logs/HO-Scrapper-{date}.log', mode="w+")
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(fh)

    # Create Instances of the Scrapper
    HOScrapper = HackerOneScrapper(logger, teleBot)

    # Start the Scrapper
    teleBot.info("----STARTING SCRAPPER----")
    HOScrapper.run()
    teleBot.info("----SCRAPPER FINISHED----")
