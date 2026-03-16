import json
import time
import datetime
import os
import traceback
from datetime import date

import requests
from requests import RequestException

from BBScrapper.model import DBSession, Program, Scope, VulnerabilityTypes, Rule, Backup
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(f'{BASE_DIR}/.env')

# We dont necessarily need Proxies in the cases of scrapping from providers
PROXIES = {}
SOURCE = "YesWeHack"


def remove_duplicates(data):
    result = []
    seen = set()
    for item in data:
        item_str = json.dumps(item, sort_keys=True)
        if item_str not in seen:
            result.append(item)
            seen.add(item_str)
    return result


def sort_data_after_date(array, sorting_key):
    return sorted(array, key=lambda x: x[sorting_key])


class YesWeHackScrapper:
    def __init__(self, logger, teleBot) -> None:
        self.db_session = DBSession()
        self.log = logger
        self.headers = {}
        self.cookies = {}

        # temporary: static token and cookies (must be refreshed manually)
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
            "Authorization": f"{os.getenv('YESWEHACK_TOKEN')}",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Origin": "https://yeswehack.com",
            "Pragma": "no-cache",
            "Referer": "https://yeswehack.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
        }
        self.cookies = {
            'navigationMod': 'hunter',
        }
        self.scraped_users = set()
        self.proxies = PROXIES
        self.session = requests.session()
        self.teleBot = teleBot

    # small DB helper
    def _safe_commit(self, context: str):
        try:
            self.db_session.commit()
        except Exception as e:
            self.db_session.rollback()
            self.log.error(f"[!] Commit failed in {context}: {e}")
            self.log.error(traceback.format_exc())

    # authentication flow
    def login(self):
        # TODO: Flow must get reimplemented

        max_attempts = 5

        for attempt in range(1, max_attempts + 1):
            self.log.info(f"Try to login number {attempt}")
            try:
                # preferred: real login via credentials
                # TODO: reimplement                

                res = self.session.get(
                    "https://yeswehack.com/user/profile",
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxies,
                    timeout=30,
                )
                time.sleep(0.2)
                if res.status_code != 200:
                    self.log.error(
                        f"Login failed! - /user/profile - {res.status_code}"
                    )
                    continue

                self.log.info("Login successful")
                return

            except Exception as e:
                self.log.error(f"Login failed with exception: {e}")
                self.log.error(traceback.format_exc())
                continue

        self.log.error("Giving up after multiple login attempts")
        raise SystemExit(1)

    # program list scraping
    def scrape_programs(self):
        self.log.info("Scraping all programs...")
        page = 1
        # some high value -> 25 is enough at the moment
        max_page = 25

        while page <= max_page:
            url = f"https://api.yeswehack.com/programs?page={page}&resultsPerPage=100"
            try:
                response = self.session.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxies,
                    timeout=30,
                )

            except RequestException as e:
                self.log.error(f"Error during fetching programs page {page}: {e}")
                self.log.error(traceback.format_exc())
                return

            if response.status_code != 200:
                self.log.error(
                    f"Error during fetching programs page {page}: "
                    f"HTTP {response.status_code}"
                )
                self.log.error(response.text)
                return

            data = response.json()
            max_page = data.get("pagination", {}).get("nb_pages", page)

            for program in data.get("items", []):
                try:
                    program_slug = program["slug"]
                    company_slug = program["business_unit"]["slug"]

                    self.parse_program(program)
                    self.get_program_scope_bounties_rules(
                        program_slug,
                        company_slug,
                        program["business_unit"].get("currency"),
                    )
                    time.sleep(0.1)

                except Exception:
                    self.log.error(f"Exception caught while processing program")
                    self.log.error(traceback.format_exc())
                    continue

            page += 1
            time.sleep(0.25)

    # program details: scopes, vuln types, rules, backup
    def get_program_scope_bounties_rules(self, slug, company_slug, currency):
        self.log.info(
            f"Scraping bounty, scope, rules, qualified vulnerabilities for: {slug}"
        )
        try:
            response = self.session.get(
                f"https://api.yeswehack.com/programs/{slug}",
                headers=self.headers,
                cookies=self.cookies,
                proxies=self.proxies,
                timeout=30,
            )
        except RequestException as e:
            self.log.error(
                f"Error while fetching bounty and scope of {slug}: {e}"
            )
            self.log.error(traceback.format_exc())
            return

        if response.status_code != 200:
            self.log.error(
                f"Error while fetching bounty and scope of {slug}: "
                f"HTTP {response.status_code}"
            )
            return

        data = response.json()
        rules = data.get("rules")
        scopes = data.get("scopes", [])
        out_of_scopes = data.get("out_of_scope", [])
        qual_vuln_types = data.get("qualifying_vulnerability", [])
        non_qual_vuln_types = data.get("non_qualifying_vulnerability", [])

        header_extension = data.get("user_agent", "")
        vpn_needed = data.get("vpn_active", False)

        # in-scope scopes
        for scope in scopes:
            db_scope = Scope(
                source=SOURCE,
                programHandle=slug,
                companyHandle=company_slug,
                type="Active",
                scope=scope.get("scope", ""),
                maxSeverity=scope.get("asset_value"),
                inScope=True,
                vpnNeeded=vpn_needed,
                headerExtension=header_extension,
            )
            self.db_session.add(db_scope)
        self._safe_commit("scopes (in-scope)")

        # out-of-scope scopes
        for scope in out_of_scopes:
            db_scope = Scope(
                source=SOURCE,
                programHandle=slug,
                companyHandle=company_slug,
                type="Active",
                scope=scope,
                inScope=False,
                vpnNeeded=vpn_needed,
                headerExtension=header_extension,
            )
            self.db_session.add(db_scope)
        self._safe_commit("scopes (out-of-scope)")

        # in-scope vulnerability types
        for vulnTypesEntries in qual_vuln_types:
            db_vulnTypes = VulnerabilityTypes(
                source=SOURCE,
                inScope=True,
                programHandle=slug,
                companyHandle=company_slug,
                vulnTypes=str(vulnTypesEntries),
            )
            self.db_session.add(db_vulnTypes)
        self._safe_commit("qualifying vulnerability types")

        # out-of-scope vulnerability types
        for vulnTypesEntries in non_qual_vuln_types:
            db_vulnTypes = VulnerabilityTypes(
                source=SOURCE,
                inScope=False,
                programHandle=slug,
                companyHandle=company_slug,
                vulnTypes=str(vulnTypesEntries),
            )
            self.db_session.add(db_vulnTypes)
        self._safe_commit("non-qualifying vulnerability types")

        # rules
        if rules is not None:
            db_rule = Rule(
                source=SOURCE,
                programHandle=slug,
                companyHandle=company_slug,
                rules=rules,
            )
            self.db_session.add(db_rule)
            self._safe_commit("rules")

        # raw backup
        db_backup = Backup(
            source=SOURCE,
            type="scope-bounties-rules",
            identifier=f"{slug}--{company_slug}",
            date=str(date.today()),
            data=json.dumps(data),
        )
        self.db_session.add(db_backup)
        self._safe_commit("scope-bounties-rules backup")

    # high-level program parsing and backup
    def parse_program(self, program):
        program_name = program.get("title", "")
        self.log.info(f"Currently parsing program: {program_name}")

        try:
            company_name = None
            company_handle = None
            currency = None

            business_unit = program.get("business_unit") or {}
            currency = business_unit.get("currency")
            company_name = business_unit.get("name")
            company_handle = business_unit.get("slug")

            db_program = (
                self.db_session.query(Program)
                .filter_by(
                    handle=program["slug"],
                    source=SOURCE,
                )
                .first()
            )

            status = "disabled" if program.get("disabled") else "active"

            max_reward = program.get("bounty_reward_max")
            min_reward = program.get("bounty_reward_min")

            if not db_program:
                db_program = Program(
                    handle=program["slug"],
                    companyName=company_name,
                    companyHandle=company_handle,
                    state=status,
                    bugCountValid=program.get("reports_count"),
                    maxReward=max_reward,
                    minReward=min_reward,
                    currency=currency,
                    source=SOURCE,
                )
                self.db_session.add(db_program)
            else:
                db_program.state = status
                db_program.bugCountValid = program.get("reports_count")
                db_program.maxReward = max_reward
                db_program.minReward = min_reward

            self._safe_commit("program upsert")

            db_backup = Backup(
                source=SOURCE,
                type="program",
                identifier=f"{program['slug']}--{company_handle}",
                date=str(date.today()),
                data=json.dumps(program),
            )
            self.db_session.add(db_backup)
            self._safe_commit("program backup")

        except Exception:
            self.log.error("Exception caught in parse_program")
            self.log.error(traceback.format_exc())

    # main entry
    def run(self):
        self.log.info("---- YesWeHackScrapper started ----")
        self.teleBot.info("YesWeHackScrapper started")

        # self.login()

        self.teleBot.info("Scraping all programs...")
        self.scrape_programs()

        self.log.info("---- YesWeHackScrapper finished ----")
        self.teleBot.info("YesWeHackScrapper finished")