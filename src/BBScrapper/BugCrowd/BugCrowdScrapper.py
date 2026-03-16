import json
import time
import os
import traceback
from datetime import datetime, date

import requests
from requests import RequestException
from bs4 import BeautifulSoup
from sqlalchemy import select
from dotenv import load_dotenv
from pathlib import Path
from BBScrapper.model import DBSession, Program, Scope, Rule, Backup

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(f'{BASE_DIR}/.env')
# We dont necessarily need Proxies in the cases of scrapping from providers
PROXIES = {}

# Important values we found out/tried to mapped
PRIORITY2SEVERITY = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low",
    5: "Info",
    None: None,
}
SOURCE = "BugCrowd"


class BugCrowdScrapper:
    def __init__(self, logger, teleBot) -> None:
        self.db_session = DBSession()
        self.log = logger
        self.scraped_user = []
        self.headers = {
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/109.0.0.0 Safari/537.36"
            )
        }
        self.cookies = {
            '_bugcrowd_session': os.getenv('BUGCROWD_SESSION'),
            'csrf-token': os.getenv('BUGCROWD_CSRF_TOKEN'),
            '_crowdcontrol_session_key': os.getenv('BUGCROWD_CROWDCONTROL'),
        }

        self.proxies = PROXIES
        self.session = requests.session()
        self.session.cookies.update(self.cookies)
        self.session.headers.update(self.headers)
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
        # TODO: Fix/Reimplement the function
        tryNum = 0
        while tryNum < 5:
            self.log.info(f"Try to login number {tryNum}")
            try:
                # ....

                url = "https://bugcrowd.com/dashboard"
                res = self.session.get(
                    url,
                    allow_redirects=False,
                    proxies=self.proxies,
                    timeout=30,
                )
                time.sleep(0.2)
                if res.status_code != 200:
                    self.log.error("Login failed!")
                    self.teleBot.error("Login failed!")
                    tryNum += 1
                    time.sleep(5)
                    continue

                self.log.info("Login successful!")
                self.teleBot.info("Login successful!")
                return True

            except RequestException as e:
                self.log.error(f"Login request exception: {e}")
                self.log.error(traceback.format_exc())
                tryNum += 1
                time.sleep(5)
            except Exception:
                self.log.error(f"Exception caught during login\n{traceback.format_exc()}")
                tryNum += 1
                time.sleep(5)

        self.log.error("Giving up...")
        self.teleBot.error("Giving up...")
        return False

    # fetch list of public programs
    def get_programs(self):
        self.log.info("Getting all public and active programs")
        programs = []
        try:
            page = 1
            while True:
                url = f"https://bugcrowd.com/engagements.json?page={page}"
                res = self.session.get(
                    url,
                    proxies=self.proxies,
                    timeout=30,
                )
                if res.status_code != 200:
                    self.log.warning(f"Error while fetching programs for url: {url}")
                    break

                data = res.json()
                total_hits = int(data["paginationMeta"]["totalCount"])
                programs += data["engagements"]
                if len(programs) >= total_hits:
                    break

                page += 1
                time.sleep(0.25)

            return programs

        except Exception:
            self.log.error(f"Exception caught in get_programs\n{traceback.format_exc()}")
            return programs

    # program metadata + backup
    def parse_program(self, program):
        try:
            program_url = program["briefUrl"]
            program_name = program["name"]
            handle = program["briefUrl"][1:]
            self.log.info(f"Currently parsing: {handle}")
            time.sleep(0.1)

            backup = program
            state = program["productEngagementType"]["label"]
            max_reward = None
            min_reward = None
            reward_summary = program.get("rewardSummary")
            if reward_summary:
                if "max_rewards" in reward_summary:
                    max_reward = float(reward_summary["max_rewards"])
                if "min_rewards" in reward_summary:
                    min_reward = float(reward_summary["min_rewards"])

            start_date = "unknown"
            if "starts_at" in program and program["starts_at"]:
                start_date = program["starts_at"]

            db_program = (
                self.db_session.query(Program)
                .filter_by(
                    handle=handle,
                    companyName=program_name,
                )
                .first()
            )

            if not db_program:
                db_program = Program(
                    source=SOURCE,
                    handle=handle,
                    programURL=program_url,
                    companyName=program_name,
                    state=state,
                    maxReward=max_reward,
                    minReward=min_reward,
                    launchedAt=start_date,
                )
                self.db_session.add(db_program)

            self._safe_commit("program upsert")

            db_backup = Backup(
                source=SOURCE,
                type="program",
                identifier=f"{handle}",
                date=str(date.today()),
                data=json.dumps(backup),
            )
            self.db_session.add(db_backup)
            self._safe_commit("program backup")

        except Exception:
            self.log.error(f"Exception caught in parse_program\n{traceback.format_exc()}")

    # fallback scope extraction via changelog
    def getScopesOldWay(self, url):
        rules = ""
        try:
            self.log.info("Try to extract the scope the old way")
            res = self.session.get(
                f"https://bugcrowd.com/{url}/changelog.json",
                proxies=self.proxies,
                timeout=30,
            )
            if res.status_code != 200:
                raise Exception(
                    f"Failed to fetch changelog.json. Status code: {res.status_code}"
                )

            changes = res.json()
            if not changes:
                raise Exception("Empty changelog.json response")

            latest_change = changes["changelogs"][0]
            change_id = latest_change["id"]

            res = self.session.get(
                f"https://bugcrowd.com{url}/changelog/{change_id}.json",
                proxies=self.proxies,
                timeout=30,
            )
            if res.status_code != 200:
                raise Exception(
                    f"Failed to fetch changelog detail. Status code: {res.status_code}"
                )

            data = res.json()
            if "data" not in data or "scope" not in data["data"]:
                raise Exception("Invalid changelog detail response structure")

            if "data" in data and "brief" in data["data"]:
                brief = data["data"]["brief"]
                rules = brief.get("description", "") + brief.get("targetsOverview", "")

            scopes = data["data"]["scope"]

            scopelist = {True: [], False: []}
            for scopeentry in scopes:
                inScope = scopeentry["inScope"]
                for target in scopeentry["targets"]:
                    potential = f"{target['uri']} - {target['name']}"
                    value = potential.replace(" - ", "")
                    if inScope:
                        scopelist[True].append(value)
                    else:
                        scopelist[False].append(value)

            return [scopelist, rules]

        except Exception as e:
            self.log.warning(f"Error collecting the scopes the old way: {e}")
            return [[], rules]

    # scope, bounty, rules and backup
    def get_program_scope_bounty_rules(self, program):
        try:
            program_url = program["briefUrl"]
            program_name = program["name"]
            curr_date = str(datetime.now())
            handle = program["briefUrl"][1:]
            self.log.info(f"Collecting scope and bounty data of {program_name}")

            url = f"https://bugcrowd.com{program_url}/target_groups"
            response = self.session.get(
                url,
                proxies=self.proxies,
                timeout=30,
            )

            # Handle non-200 responses and try fallback
            if response.status_code != 200:
                self.log.info(
                    f"Error while fetching scope groups of program {program_name} "
                    f"(status={response.status_code})"
                )

                html_content = response.text
                soup = BeautifulSoup(html_content, "html.parser")
                element = soup.find(
                    "a",
                    class_="bc-link",
                    href="/settings/two_factor_auth",
                    text="Enable 2FA",
                )
                if element:
                    self.log.warning("Reason for the error: Enable 2FA")

                # fallback: old way via changelog
                scopesManually, rules = self.getScopesOldWay(program_url)

                # store manual in-scope scopes
                for scope in scopesManually.get(True, []):
                    db_scope_new = Scope(
                        source=SOURCE,
                        programHandle=handle,
                        type="Active-Manually",
                        inScope=True,
                        scope=scope,
                        date=str(curr_date),
                    )
                    self.db_session.add(db_scope_new)

                # store manual out-of-scope scopes
                for scope in scopesManually.get(False, []):
                    db_scope_new = Scope(
                        source=SOURCE,
                        programHandle=handle,
                        type="Active-Manually",
                        inScope=False,
                        scope=scope,
                        date=str(curr_date),
                    )
                    self.db_session.add(db_scope_new)

                self._safe_commit("manual scopes")

                # store manual rules
                db_rule = Rule(
                    source=SOURCE,
                    programHandle=handle,
                    companyName=program_name,
                    rules=rules,
                    date=curr_date,
                )
                self.db_session.add(db_rule)
                self._safe_commit("manual rules")

                return

            # Try to parse JSON safely
            try:
                data = response.json()
            except ValueError:
                self.log.info(
                    f"Non-JSON response while fetching scope groups of program {program_name}"
                )
                self.log.debug(f"Raw response (truncated): {response.text[:1000]}")

                # fallback: old way via changelog
                scopesManually, rules = self.getScopesOldWay(program_url)

                for scope in scopesManually.get(True, []):
                    db_scope_new = Scope(
                        source=SOURCE,
                        programHandle=handle,
                        type="Active-Manually",
                        inScope=True,
                        scope=scope,
                        date=str(curr_date),
                    )
                    self.db_session.add(db_scope_new)

                for scope in scopesManually.get(False, []):
                    db_scope_new = Scope(
                        source=SOURCE,
                        programHandle=handle,
                        type="Active-Manually",
                        inScope=False,
                        scope=scope,
                        date=str(curr_date),
                    )
                    self.db_session.add(db_scope_new)

                self._safe_commit("manual scopes")

                db_rule = Rule(
                    source=SOURCE,
                    programHandle=handle,
                    companyName=program_name,
                    rules=rules,
                    date=curr_date,
                )
                self.db_session.add(db_rule)
                self._safe_commit("manual rules")

                return

            if not isinstance(data, dict):
                self.log.warning(
                    f"Unexpected JSON structure for program {program_name}: {type(data)}"
                )
                return

            # Extract and store rules overview from HTML
            overview = data.get("overview", "")
            soup = BeautifulSoup(overview, "html.parser")
            additional_description = soup.get_text(separator=" ", strip=True)

            db_rule = Rule(
                source=SOURCE,
                programHandle=handle,
                companyName=program_name,
                rules=additional_description,
                date=curr_date,
            )
            self.db_session.add(db_rule)
            self._safe_commit("rules")

            # Iterate scope groups and fetch targets
            for scope_group in data.get("groups", []):
                time.sleep(0.1)
                group_id = scope_group["id"]
                group_url = scope_group["targets_url"]

                res = self.session.get(
                    f"https://bugcrowd.com{group_url}",
                    proxies=self.proxies,
                    timeout=30,
                )
                if res.status_code != 200:
                    self.log.warning(
                        f"Error while fetching scope group {group_url} of program "
                        f"{program_name} (status={res.status_code})"
                    )
                    continue

                try:
                    targets_data = res.json()
                except ValueError:
                    self.log.warning(
                        f"Non-JSON response for targets of group {group_url} "
                        f"for program {program_name}"
                    )
                    self.log.debug(f"Raw targets response (truncated): {res.text[:1000]}")
                    continue

                # in-scope targets
                if scope_group.get("in_scope"):
                    for target in targets_data.get("targets", []):
                        target_name = target["name"]

                        target_tags = []
                        if "target" in target and "tags" in target["target"]:
                            for tag in target["target"]["tags"]:
                                target_tags.append(tag["name"])

                        new_scope = Scope(
                            source=SOURCE,
                            programHandle=handle,
                            type="Active",
                            inScope=True,
                            scope=target_name,
                            bountyIdentifier=group_id,
                            tags=json.dumps(target_tags),
                            date=str(curr_date),
                        )
                        self.db_session.add(new_scope)
                        self._safe_commit("in-scope targets")

                # out-of-scope targets
                else:
                    out_of_scope_scopes = []
                    for target in targets_data.get("targets", []):
                        scope_name = target["name"]
                        tags = []
                        if "target" in target and "tags" in target["target"]:
                            for tag in target["target"]["tags"]:
                                tags.append(tag["name"])

                        out_of_scope_scopes.append(
                            {
                                "scope": scope_name,
                                "tags": tags,
                            }
                        )

                    for scope in out_of_scope_scopes:
                        db_out_of_scope = Scope(
                            source=SOURCE,
                            programHandle=handle,
                            scope=scope["scope"],
                            tags=json.dumps(scope["tags"]),
                            inScope=False,
                        )
                        self.db_session.add(db_out_of_scope)
                        self._safe_commit("out-of-scope targets")

            # Store backup of raw JSON
            db_backup = Backup(
                source=SOURCE,
                type="program-bounty-scope-rules",
                identifier=f"{handle}",
                date=str(date.today()),
                data=json.dumps(data),
            )
            self.db_session.add(db_backup)
            self._safe_commit("program-bounty-scope-rules backup")

        except Exception:
            self.log.error(
                f"Exception caught in get_program_scope_bounty_rules\n"
                f"{traceback.format_exc()}"
            )

    # orchestrate all program scraping
    def scrape_programs(self):
        self.log.info("Scraping programs...")
        programs = self.get_programs()
        for program in programs:
            self.parse_program(program)
            time.sleep(0.3)
            self.get_program_scope_bounty_rules(program)
            time.sleep(0.3)

    # main entry
    def run(self):
        self.log.info("---- BugCrowdScrapper started ----")
        self.teleBot.info("BugCrowdScrapper started")

        #self.login()
        
        self.teleBot.info("Scraping programs...")
        self.scrape_programs()

        self.log.info("---- BugCrowdScrapper finished ----")
        self.teleBot.info("BugCrowdScrapper finished")
