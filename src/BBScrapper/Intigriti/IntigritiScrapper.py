import json
import time
import traceback
import requests
import os

from datetime import datetime, date
from requests import RequestException
from bs4 import BeautifulSoup
from BBScrapper.model import DBSession, Program, Scope, VulnerabilityTypes, Rule, Backup
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(f'{BASE_DIR}/.env')
# We dont necessarily need Proxies in the cases of scrapping from providers
PROXIES = {}
SOURCE = "Intigriti"

# Important values we found out/tried to mapped
STATE2STATUS = {1: "1", 2: "2", 3: "open", 4: "suspended", 5: "closed"}
ACTIVITYTYPE2STRING = {
    19: "publish program update",
    18: "unsuspend program",
    17: "update confidentiality level to public",
    16: "update confidentiality level to registered",
    15: "update confidentiality level to application",
    13: "suspend program",
    12: "launch program",
    11: "close submission",
    10: "accept submission",
    9: "create submission",
    8: "change rules of engagement",
    7: "change fqa",
    6: "change severity assessment",
    5: "change bounties",
    4: "change domains",
    3: "change out of scope",
    2: "change in scope",
}


def sort_data_after_date(array, sorting_key):
    return sorted(array, key=lambda x: x[sorting_key])


class IntigritiScrapper:
    def __init__(self, logger, teleBot) -> None:
        self.db_session = DBSession()
        self.headers = {
            "authority": "app.intigriti.co",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "referer": "https://app.intigriti.com/researcher/dashboard",
            "accept": "application/json, text/plain, */*",
            "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
            "cache-control": "no-cache",
        }
        self.cookies = {
            '__Host-Intigriti.Web.Researcher': os.getenv('INTIGRITI_SESSION'),
            '__Host-Intigriti.CsrfToken.Researcher': os.getenv('INTIGRITI_CSRF'),
            'intercom-session-pf15mvw4': os.getenv('INTIGRITI_INTERCOM_SESSION'),
        }
        self.proxies = PROXIES
        self.session = requests.session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        self.log = logger
        self.teleBot = teleBot

    # small DB helper
    def _safe_commit(self, context: str):
        try:
            self.db_session.commit()
        except Exception as e:
            self.db_session.rollback()
            self.log.error(f"[!] Commit failed in {context}: {e}")
            self.log.error(traceback.format_exc())

    def login(self):
        # TODO: Fix the login flow
        idx = 0
        max_attempts = 5

        while idx < max_attempts:
            self.log.info(f"Try to login number {idx}")
            try:
                url = "https://login.intigriti.com:443/account/login"
                res = self.session.get(url, proxies=self.proxies, timeout=30)

                soup = BeautifulSoup(res.text, "html.parser")
                input_element = soup.select('input[name="__RequestVerificationToken"]')
                if not input_element:
                    self.log.error("Could not find __RequestVerificationToken input")
                    idx += 1
                    time.sleep(5)
                    continue

                request_verification_token = input_element[0].get("value")

                data = {
                    "Input.ReturnUrl": "",
                    "Input.Email": INTIGRITI_EMAIL,
                    "Input.Password": INTIGRITI_PASSWORD,
                    "button": "login",
                    "Input.WebHostUrl": "https://app.intigriti.com",
                    "Input.LocalLogin": "True",
                    "__RequestVerificationToken": request_verification_token,
                    "Input.RememberLogin": "false",
                }

                self.session.post(
                    url,
                    data=data,
                    proxies=self.proxies,
                    timeout=30,
                )

                token_url = "https://app.intigriti.com/auth/token"
                res = self.session.get(
                    token_url,
                    proxies=self.proxies,
                    timeout=30,
                )
                token = res.text.strip('"')
                self.session.headers.update({"Authorization": f"Bearer {token}"})

                check_url = "https://app.intigriti.com/api/core/researcher/programs"
                response = self.session.get(
                    check_url,
                    proxies=self.proxies,
                    timeout=30,
                )
                if response.status_code == 200:
                    self.log.info("Intigriti login successful")
                    return
                else:
                    self.log.error(
                        f"Login seems invalid, status {response.status_code}"
                    )
                    idx += 1
                    time.sleep(5)
                    continue

            except Exception:
                self.log.error("Exception caught during Intigriti login")
                self.log.error(traceback.format_exc())
                idx += 1
                time.sleep(5)
                continue

        self.log.error("Giving up after multiple Intigriti login attempts")
        raise SystemExit(1)

    # program list scraping
    def scrape_programs(self):
        try:
            url = "https://app.intigriti.com/api/core/researcher/programs"
            response = self.session.get(
                url,
                proxies=self.proxies,
                timeout=30,
            )
            response.raise_for_status()  # wirft bei != 200 eine Exception
        except RequestException as e:
            self.log.error(f"Error while fetching the programs: {e}")
            self.log.error(traceback.format_exc())
            return

        # Parsing the fetched data
        data = response.json()
        for program in data:
            try:
                company_handle = program.get("companyHandle")
                program_handle = program.get("handle")

                if program_handle is None:
                    continue

                # only programs with full visibility for me (confidentialityLevel 4)
                if program.get("confidentialityLevel") != 4:
                    self.log.warning(
                        f"Check if terms need to be accepted: "
                        f"{company_handle}-{program_handle}"
                    )
                    continue

                self.log.info(
                    f"Fetching additional information for program: {program_handle}"
                )
                detail_url = (
                    f"https://app.intigriti.com/api/core/researcher/programs/"
                    f"{company_handle}/{program_handle}"
                )

                # Fetch details for each of the programs
                try:
                    response = self.session.get(detail_url, proxies=self.proxies, timeout=30)
                    response.raise_for_status()
                except RequestException as e:
                    self.log.error(
                        f"Error while fetching additional information for program "
                        f"{program_handle}: {e}"
                    )
                    self.log.error(traceback.format_exc())

                    self.parse_program(program, additional_info=False)

                    db_backup = Backup(
                        source=SOURCE,
                        type="program",
                        identifier=f"{company_handle}-{program_handle}",
                        date=str(date.today()),
                        data=json.dumps(program),
                    )
                    self.db_session.add(db_backup)
                    self._safe_commit("program backup (no additional info)")
                    continue

                data_addition = response.json()
                description = data_addition.get("description", "")
                scope_and_bounty_data = {
                    "programHandle": program_handle,
                    "companyHandle": company_handle,
                    # neu: assetsAndGroups statt domains
                    "domains": data_addition.get("assetsAndGroups", []),
                    "bounties": data_addition.get("bountyTables", []),
                }


                vuln_types_and_rules = {
                    "programHandle": program_handle,
                    "companyHandle": company_handle,
                    "inScopes": data_addition.get("inScopes", []),
                    "outOfScopes": data_addition.get("outOfScopes", []),
                    "rules": {
                        "rules": data_addition.get("rulesOfEngagements", []),
                        "desc": description,
                    },
                }

                self.parse_scope(scope_and_bounty_data)
                self.parse_vulnerabilityTypes_and_rules(vuln_types_and_rules)
                self.parse_program(program | data_addition, additional_info=True)

    
                db_backup = Backup(
                    source=SOURCE,
                    type="program",
                    identifier=f"{company_handle}-{program_handle}",
                    date=str(date.today()),
                    data=json.dumps(program | data_addition),
                )
                self.db_session.add(db_backup)
                self._safe_commit("program backup (with additional info)")
                time.sleep(0.25)

            except Exception as e:
                self.log.error(f"Exception caught in scrape_programs: {e}")
                self.log.error(traceback.format_exc())

    # vulnerability types and rules parsing
    def parse_vulnerabilityTypes_and_rules(self, data):
        try:
            programHandle = data["programHandle"]
            companyHandle = data["companyHandle"]

            # process in-scope and out-of-scope texts
            scopes = {
                True: data.get("inScopes", []),
                False: data.get("outOfScopes", []),
            }

            print(scopes)
            exit()

            for inScope, entries in scopes.items():
                if not entries:
                    continue

                latest_entry = sort_data_after_date(entries, "createdAt")[-1]
                created_at = datetime.fromtimestamp(
                    latest_entry["createdAt"]
                ).isoformat()

                vuln_text = latest_entry["content"]["content"]

                vuln_obj = VulnerabilityTypes(
                    source=SOURCE,
                    inScope=inScope,
                    programHandle=programHandle,
                    companyHandle=companyHandle,
                    vulnTypes=json.dumps(vuln_text),
                    date=created_at,
                )
                self.db_session.add(vuln_obj)

            self._safe_commit("vulnerability types")

            # process latest rules of engagement
            rule_entries = data.get("rules", {}).get("rules", [])
            if not rule_entries:
                return

            latest_rule = sort_data_after_date(rule_entries, "createdAt")[-1]
            created_at_rule = datetime.fromtimestamp(
                latest_rule["createdAt"]
            ).isoformat()

            rule_payload = {
                "rule": latest_rule,
                "desc": data.get("rules", {}).get("desc", ""),
            }

            rule_obj = Rule(
                source=SOURCE,
                programHandle=programHandle,
                companyHandle=companyHandle,
                rules=json.dumps(rule_payload),
                date=created_at_rule,
            )
            self.db_session.add(rule_obj)

            self._safe_commit("rules")

        except Exception:
            self.log.error("Exception caught in parse_vulnerabilityTypes_and_rules")
            self.log.error(traceback.format_exc())


    # scope parsing
    def parse_scope(self, data):
        try:
            programHandle = data["programHandle"]
            companyHandle = data["companyHandle"]

            # get scope groups (assetsAndGroups)
            scope_groups = data.get("domains", [])
            if not scope_groups:
                self.log.info(f"No scope groups for {companyHandle}/{programHandle}")
                return

            # use latest scope group only
            latest_group = sort_data_after_date(scope_groups, "createdAt")[-1]
            created_at_dt = datetime.fromtimestamp(latest_group["createdAt"])
            createdAt = created_at_dt.isoformat()

            # iterate all assets in latest group
            assets = latest_group.get("content", [])

            for asset in assets:
                scope = asset["name"]
                bountyIdentifier = asset.get("bountyTierId")

                # This means out-of-scope
                inScopeVar = True
                if bountyIdentifier == 5:
                    inScopeVar = False
                    bountyIdentifier = None

                new_scope = Scope(
                    source=SOURCE,
                    programHandle=programHandle,
                    companyHandle=companyHandle,
                    bountyIdentifier=None,
                    maxSeverity=str(bountyIdentifier) if bountyIdentifier else None,
                    type="Active",
                    inScope=inScopeVar,
                    scope=scope,
                    date=createdAt,
                )
                self.db_session.add(new_scope)

            self._safe_commit("scope")

        except Exception:
            self.log.error("Exception caught in parse_scope")
            self.log.error(traceback.format_exc())


    # program parsing and basic metadata
    def parse_program(self, program, additional_info):
        try:
            program_name = program["handle"]
            self.log.info(f"Currently parsing program {program_name} ...")

            currency = None
            min_reward = None
            if "minBounty" in program:
                min_reward = program["minBounty"]["value"]
                currency = program["minBounty"]["currency"]

            max_reward = None
            if "maxBounty" in program:
                max_reward = program["maxBounty"]["value"]
                currency = program["minBounty"]["currency"]

            db_program = (
                self.db_session.query(Program)
                .filter_by(
                    programId=program["programId"],
                    source=SOURCE,
                )
                .first()
            )

            bug_count_valid = None
            bug_count_overall = None
            if additional_info:
                bug_count_valid = program.get("acceptedSubmissionCount")
                bug_count_overall = program.get("submissionCount")

            if not db_program:
                db_program = Program(
                    programId=program["programId"],
                    handle=program["handle"],
                    companyName=program["companyName"],
                    companyHandle=program["companyHandle"],
                    state=STATE2STATUS.get(program["status"]),
                    bugCountValid=bug_count_valid,
                    bugCountOverall=bug_count_overall,
                    maxReward=max_reward,
                    minReward=min_reward,
                    currency=currency,
                    triageActive=bool(not program.get("skipTriage")),
                    source=SOURCE,
                )
                self.db_session.add(db_program)

            self._safe_commit("program upsert")

        except Exception:
            self.log.error("Exception caught in parse_program")
            self.log.error(traceback.format_exc())

    # main entry point
    def run(self):
        self.log.info("---- IntigritiScrapper started ----")
        self.teleBot.info("IntigritiScrapper started")

        #self.login()

        self.teleBot.info("Scraping programs...")
        self.scrape_programs()

        self.log.info("---- IntigritiScrapper finished ----")
        self.teleBot.info("IntigritiScrapper finished")
