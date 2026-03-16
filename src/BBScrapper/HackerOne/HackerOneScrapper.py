import json
import time
import os
import traceback
from datetime import datetime, date

import requests
from requests import RequestException
from bs4 import BeautifulSoup

from BBScrapper.model import DBSession, Program, Scope, Rule, Backup
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(f'{BASE_DIR}/.env')
# We dont necessarily need Proxies in the cases of scrapping from providers
PROXIES = {}


SOURCE = "HackerOne"


def sort_data(data, key):
    return sorted(data, key=lambda x: x[key])


class HackerOneScrapper:
    def __init__(self, logger, teleBot) -> None:
        self.db_session = DBSession()
        self.proxies = PROXIES
        self.scraped_users = []
        self.session = requests.session()
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

    # authentication flow
    def login(self):
        max_attempts = 3
        tryNum = 0

        while tryNum < max_attempts:
            self.log.info(f"Try to login number {tryNum}")
            try:
                url = "https://hackerone.com:443/users/sign_in"
                headers = {}
                res = self.session.get(
                    url,
                    headers=headers,
                    proxies=self.proxies,
                    timeout=30,
                )
                if res.status_code != 200:
                    self.log.error(f"Login failed with status code {res.status_code}")
                    tryNum += 1
                    time.sleep(5)
                    continue

                time.sleep(1)
                soup = BeautifulSoup(res.text, "html.parser")
                csrf_meta = soup.find("meta", attrs={"name": "csrf-token"})
                if not csrf_meta or not csrf_meta.get("content"):
                    self.log.error("No CSRF token meta tag found on sign_in page")
                    tryNum += 1
                    time.sleep(5)
                    continue
                csrf = csrf_meta["content"]

                url = "https://hackerone.com:443/graphql"
                data = {
                    "operationName": "SignIn",
                    "query": (
                        "query SignIn {\n  me {\n    id\n    __typename\n  }\n  session {\n"
                        "    id\n    csrf_token\n    __typename\n  }\n}\n"
                    ),
                    "variables": {},
                }
                headers["X-Csrf-Token"] = csrf
                res = self.session.post(
                    url,
                    headers=headers,
                    json=data,
                    proxies=self.proxies,
                    timeout=30,
                )
                if res.status_code != 200:
                    self.log.error(f"Login failed with status code {res.status_code}")
                    tryNum += 1
                    time.sleep(5)
                    continue

                time.sleep(1)
                try:
                    json_res = res.json()
                except ValueError:
                    self.log.error("Failed to parse JSON during SignIn GraphQL step")
                    self.log.debug(f"Raw response (truncated): {res.text[:1000]}")
                    tryNum += 1
                    time.sleep(5)
                    continue

                csrf = json_res.get("data", {}).get("session", {}).get("csrf_token")
                if not csrf:
                    self.log.error("No CSRF token in SignIn GraphQL response")
                    tryNum += 1
                    time.sleep(5)
                    continue

                url = "https://hackerone.com:443/sessions"
                data = {
                    "email": os.getenv('HACKERONE_EMAIL'),
                    "password": os.getenv('HACKERONE_PASSWORD'),
                    "remember_me": "true",
                    "fingerprint": "xxxx",
                }
                headers["X-Csrf-Token"] = csrf
                res = self.session.post(
                    url,
                    headers=headers,
                    data=data,
                    proxies=self.proxies,
                    timeout=30,
                )
                if res.status_code != 200:
                    self.log.error(f"Login failed with status code {res.status_code}")
                    tryNum += 1
                    time.sleep(5)
                    continue

                time.sleep(1)
                if res.headers.get("content-type", "").startswith("application/json"):
                    try:
                        json_res = res.json()
                    except ValueError:
                        self.log.error("Failed to parse JSON during credential login")
                        self.log.debug(f"Raw response (truncated): {res.text[:1000]}")
                        tryNum += 1
                        time.sleep(5)
                        continue

                    if json_res.get("result_code") == "valid-credentials":
                        res = self.session.get(
                            "https://hackerone.com/opportunities/all",
                            proxies=self.proxies,
                            timeout=30,
                        )
                        if res.status_code == 200:
                            soup = BeautifulSoup(res.text, "html.parser")
                            csrf_meta = soup.find(
                                "meta", attrs={"name": "csrf-token"}
                            )
                            if not csrf_meta or not csrf_meta.get("content"):
                                self.log.error(
                                    "No CSRF token meta tag found on opportunities page"
                                )
                                tryNum += 1
                                time.sleep(5)
                                continue

                            csrf_token = csrf_meta["content"]
                            self.session.headers.update({"x-csrf-token": csrf_token})
                            self.log.info("Login with credentials successful")
                            self.teleBot.info("Login with credentials successful")
                            return

                self.log.error("Login failed with credentials")

            except RequestException as e:
                self.log.error(f"Login request exception: {e}")
                self.log.error(traceback.format_exc())
                tryNum += 1
                time.sleep(5)
            except Exception:
                self.log.error(f"Exception caught in login\n{traceback.format_exc()}")
                tryNum += 1
                time.sleep(5)

        self.log.error("Trying backup session")
        self.teleBot.error("Login failed - trying backup cookies")

        cookies = {
            'rm_sLqSAErKFkmmugkG9Fxg': '{%22$uid%22:%22194bc8a87dd-25b07a62-ce71-461a-9601-882d6198542d%22}',
            'lo-uid': '8bf02824-1738329983324-e960421c6f0868b1',
            'lo-visits': '37',
            'notice_preferences': '0:',
            'TAconsentID': '777a24af-6aa8-4440-bd25-e7f13a5be9be',
            'notice_gdpr_prefs': '0:',
            'cmapi_gtm_bl': 'ga-ms-ua-ta-asp-bzi-sp-awct-cts-csm-img-flc-fls-mpm-mpr-m6d-tc-tdc',
            'cmapi_cookie_privacy': 'permit 1 required',
            'h1_device_id': '80f27460-5734-4889-aca1-3443b46c9e7c',
            'intercom-device-id-zlmaz2pu': 'f4462cc8-cf82-44ae-8e11-286152d3bd3f',
            '__stripe_mid': '95dbd6db-ebab-4c90-9d9c-c3ee5e4ae11eefe141',
            '__stripe_sid': '18e346a8-a1c9-4a8b-a34d-88ab06440c278e97dd',
            'cf_clearance': 'N3V0v5z8o9BTp.gVSjcLEiM8mshefnUWOleIVW1HYrs-1769263961-1.2.1.1-RaOouHNJ_NIJLXDWUKHqjle06_x3x2cmt_ey.lGI4wuGzjoN66POTeex1a2DtFcOTAN3hTLIc3w1GTSrgL6E5YzhNx14RyWaYD0S4iJ2TPrjmaUWe_8qoYbosYP4emq_h7fYJxfwSYrMG8FEP9I4GP5G8QOZyIwPpAm6tSPHhKOaV6aFY6YOQnt76yFxFfC..DjbgmxYGUJUCMwsQIiKnd0ZPZqmqnNIlyH2pSJ1m44',
            'app_signed_in': 'true',
            'intercom-session-zlmaz2pu': 'NlVKb1dBVzZORFNlclRTV2FQYTY1T3lEaFBWTHVpa1hyTGN6dWsxYklYRzZSbk9LMmJqek1LeEgxV05Sc3JzVU40clNYVHZBT01rdXpSSVgxMUhrWS8rVFFLSldibm5wdXUzWnVqV2FoVUE9LS13clAzSXhwd2VUcU84dllSdkpPcnZ3PT0=--a4fbf363bf7c3cb1824090425f076c70899c6f9d',
            '_dd_s': 'rum=0&expire=1769264964465',
            '__Host-session': 'NDA1MHk3Mmt2Z3FFdHREcGd2Rmp3aVczQnVqUDRKTGZ5Y2UxZkdEcFRHNmdQcFZUSVRtSUJwVlJ4VUZqWHZxT1pCbWRINU5nY1ZkTTQ1QmtQcGtZeXlVRTNNUDB4SUczd2ZnT25JRVhVU2QrL2pTQ1hYcU9ESGlsbS9YUC8xbzRhblVDNGduOEk2SlJWUEo0ZTFSdklmN0cyRTB6bmc2NEFtdldIaGpKTkhQL05WNE1CQVZqcTJCQmNackRjdU1sSmpRbXZVSzZQa1hzTFV6aDQ3VW53dzl6SXNMeWhpLy84empuR3g3bnlSYUltTWs1Z3ROTWtMRWI0SUorTkVZSDdMRE1FNnVGa2dCcmZld1QyaDcveFd0WmxodUtuanVXRlVudFpKT09XMW9XZFdaU2VkdWFkanIwckxwR2VrNk9QOXRQWUhzamlmYmV4cE1TS2dDQWtQaDFURGIvalZuRkw3S2c1VStjRlFhcGZ2b3B3dTBvZXVZOWdmcU9zeFJGeUZtWTZIdGdBaFpSbEZNNkdQYWtXZmQwRkxBWW1QS0ZuNytUUHF2dWdZMlE5bkhTdUhYQzdOeDRyVktTeDYzeWdiTWlrTGF4RWhtcmRqRndLOE5jUFhOQmtDUjNUNTdoNnBhamN6OUtaeHFLOWZHbE5yMmRYVjRVMzM3UWRHajNqemlDN2NzZmZPMmJVcndmSnVkWittOEI1cmpSWkxNaTFLSEdDcE9RNHhHdldSRUl6Wkt6amVkL3JmMU9qWjZGTjBiZUNWemhzTk4vcyttc1NkRkZkUXZlOWY4dC96ajFodDlRQnRzblBYZ3FXVlduWHRiMkhZOWhURDhja3NNWEFmclRPYWU0VEtKdDdIR2xrNDhPRHQxY2xOeko2N0RuOTBYNnZNUkEwRXM9LS1ScjNFRGd5K0FsaGpmZ3lOTVpEbmVnPT0%3D--c2a19613962e27cf1b28b5d9d664e752ff0a91c2',
        }

        cookies = {
            '__Host-session': os.getenv('H1_SESSION'),
            'cf_clearance': os.getenv('H1_CF_CLEARANCE'),
            'h1_device_id': os.getenv('H1_DEVICE_ID'),
            '__stripe_mid': os.getenv('H1_STRIPE_MID'),
            '__stripe_sid': os.getenv('H1_STRIPE_SID'),
        }
        self.session = requests.session()
        self.session.cookies.update(cookies)

        try:
            res = self.session.get(
                "https://hackerone.com/settings/profile/edit",
                allow_redirects=False,
                proxies=self.proxies,
                timeout=30,
            )
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "html.parser")
                csrf_meta = soup.find("meta", attrs={"name": "csrf-token"})
                if not csrf_meta or not csrf_meta.get("content"):
                    self.log.error(
                        "No CSRF token meta tag found on profile edit page (backup)"
                    )
                    self.teleBot.error(
                        "Error while login - update credentials for HackerOne!"
                    )
                    raise SystemExit(1)

                csrf_token = csrf_meta["content"]
                self.session.headers.update({"x-csrf-token": csrf_token})
                self.log.info("Login using backup cookies successfully")
                self.teleBot.info("Login using backup cookies successfully")
                return
            else:
                self.log.error("Login using backup cookies failed")
                self.teleBot.error("Error while login - update credentials for HackerOne!")
                raise SystemExit(1)

        except Exception:
            self.log.error(f"Exception caught during backup login\n{traceback.format_exc()}")
            self.teleBot.error("Login failed - Scraper stopped")
            raise SystemExit(1)

    # program list + scopes + rules
    def scrape_programs(self):
        try:
            self.log.info("Scraping all programs...")
            cursor = None
            json_data = {
                'operationName': 'DiscoveryQuery',
                'variables': {
                    'size': 24,
                    'from': 0,
                    'cursor': None,
                    'query': {
                        'query_string': {
                            'query': '*Superhuman (formerly Grammarly)*',
                            'fields': [
                                'name^600',
                                'handle^500',
                                'asset_identifier^400',
                                'tech^300',
                                'industry^200',
                                'policy',
                            ],
                            'analyze_wildcard': True,
                            'minimum_should_match': 1,
                        },
                    },
                    'filter': {
                        'bool': {
                            'filter': [
                                {
                                    'bool': {
                                        'must_not': {
                                            'term': {
                                                'team_type': 'Engagements::Assessment',
                                            },
                                        },
                                    },
                                },
                                None,
                            ],
                        },
                    },
                    'sort': [
                        {
                            'field': 'launched_at',
                            'direction': 'DESC',
                        },
                    ],
                    'post_filters': {
                        'my_programs': False,
                        'bookmarked': False,
                        'campaign_teams': False,
                    },
                    'product_area': 'opportunity_discovery',
                    'product_feature': 'search',
                },
                'query': 'query DiscoveryQuery($query: OpportunitiesQuery!, $filter: QueryInput!, $from: Int, $size: Int, $sort: [SortInput!], $post_filters: OpportunitiesFilterInput) {\n  me {\n    id\n    ...OpportunityListMeElastic\n    __typename\n  }\n  opportunities_search(\n    query: $query\n    filter: $filter\n    from: $from\n    size: $size\n    sort: $sort\n    post_filters: $post_filters\n  ) {\n    nodes {\n      ... on OpportunityDocument {\n        id\n        handle\n        state\n        __typename\n      }\n      ...OpportunityList\n      __typename\n    }\n    total_count\n    __typename\n  }\n}\n\nfragment OpportunityListMeElastic on User {\n  id\n  ...OpportunityCardMeElastic\n  __typename\n}\n\nfragment OpportunityCardMeElastic on User {\n  id\n  ...BookmarkMe\n  ...PrivateOpportunitiesMe\n  __typename\n}\n\nfragment BookmarkMe on User {\n  id\n  __typename\n}\n\nfragment PrivateOpportunitiesMe on User {\n  id\n  whitelisted_teams {\n    edges {\n      node {\n        id\n        _id\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment OpportunityList on OpportunityDocument {\n  id\n  ...OpportunityCard\n  __typename\n}\n\nfragment OpportunityCard on OpportunityDocument {\n  id\n  team_id\n  name\n  handle\n  profile_picture\n  triage_active\n  publicly_visible_retesting\n  allows_private_disclosure\n  allows_bounty_splitting\n  launched_at\n  state\n  offers_bounties\n  last_updated_at\n  currency\n  team_type\n  minimum_bounty_table_value\n  maximum_bounty_table_value\n  cached_response_efficiency_percentage\n  first_response_time\n  structured_scope_stats\n  show_response_efficiency_indicator\n  submission_state\n  resolved_report_count\n  campaign {\n    id\n    campaign_type\n    start_date\n    end_date\n    critical\n    target_audience\n    __typename\n  }\n  gold_standard\n  awarded_report_count\n  awarded_reporter_count\n  h1_clear\n  idv\n  list_opportunity\n  __typename\n}\n',
            }

            while True:
                try:
                    response = self.session.post(
                        "https://hackerone.com/graphql",
                        json=json_data,
                        proxies=self.proxies,
                        timeout=30,
                    )
                except RequestException as e:
                    self.log.error(f"Error while fetching programs: {e}")
                    self.log.error(traceback.format_exc())
                    break

                if response.status_code != 200:
                    self.log.error(f"Error while fetching programs (status={response.status_code})")
                    self.log.debug(f"Raw response (truncated): {response.text[:1000]}")
                    break

                try:
                    result = response.json()
                except ValueError:
                    self.log.error("Non-JSON response while fetching programs")
                    self.log.debug(f"Raw response (truncated): {response.text[:1000]}")
                    break

                if result.get("errors"):
                    self.log.error(f"GraphQL errors: {result['errors']}")
                    break

                data = result.get("data") or {}
                search = data.get("opportunities_search") or {}

                programs = search.get("nodes") or []

                for node in programs:
                    try:
                        self.parse_program(node)
                        self.scrape_scope_and_bounty(node["handle"])
                        self.scrape_rules(node["handle"])
                    except Exception:
                        self.log.error(f"Exception caught in inner loop\n{traceback.format_exc()}")
                        continue

                page_info = search.get("page_info") or {}

                has_next = page_info.get("has_next_page", False)
                cursor = page_info.get("end_cursor")

                if not has_next:
                    break

                json_data["variables"]["cursor"] = cursor
                time.sleep(0.5)

        except Exception:
            self.log.error(f"Exception caught before loop in scrape_programs\n{traceback.format_exc()}")


    # rules / policy versions
    def scrape_rules(self, program_handle):
        self.log.info(
            f"Scraping rules and vulnerability types of program {program_handle}"
        )
        time.sleep(0.1)
        try:
            response = self.session.get(
                f"https://hackerone.com/{program_handle}/policy_versions",
                proxies=self.proxies,
                timeout=30,
            )
        except RequestException as e:
            self.log.error(
                f"Error while scraping rules of program {program_handle}: {e}"
            )
            self.log.error(traceback.format_exc())
            return

        if response.status_code != 200:
            self.log.error(
                f"Error while scraping rules of program {program_handle}, "
                f"status {response.status_code}"
            )
            self.log.debug(f"Raw response (truncated): {response.text[:1000]}")
            return

        try:
            data = response.json()
        except ValueError:
            self.log.error(
                f"Non-JSON response while scraping rules of program {program_handle}"
            )
            self.log.debug(f"Raw response (truncated): {response.text[:1000]}")
            return

        if not data:
            return

        ruleUpdatesSorted = sort_data(data, "timestamp")
        ruleUpdate = ruleUpdatesSorted[-1]

        try:
            db_rule = Rule(
                source=SOURCE,
                programHandle=program_handle,
                rules=ruleUpdate["new_policy"],
                date=ruleUpdate["timestamp"],
            )
            self.db_session.add(db_rule)
            self._safe_commit("rules")

        except Exception:
            self.log.error(f"Exception caught in scrape_rules\n{traceback.format_exc()}")

    # scope and bounty data
    def scrape_scope_and_bounty(self, program_handle):
        try:
            json_data = {
                "operationName": "PolicySearchStructuredScopesQuery",
                "variables": {
                    "handle": program_handle,
                    "searchString": "",
                    "eligibleForSubmission": None,
                    "eligibleForBounty": None,
                    "asmTagIds": [],
                    "assetTypes": [],
                    "from": 0,
                    "size": 100,
                    "sort": {"field": "cvss_score", "direction": "DESC"},
                    "product_area": "h1_assets",
                    "product_feature": "policy_scopes",
                },
                "query": "query PolicySearchStructuredScopesQuery($handle: String!, $searchString: String, $eligibleForSubmission: Boolean, $eligibleForBounty: Boolean, $minSeverityScore: SeverityRatingEnum, $asmTagIds: [Int], $assetTypes: [StructuredScopeAssetTypeEnum!], $from: Int, $size: Int, $sort: SortInput) {\n  team(handle: $handle) {\n    id\n    team_display_options {\n      show_total_reports_per_asset\n      __typename\n    }\n    structured_scopes_search(\n      search_string: $searchString\n      eligible_for_submission: $eligibleForSubmission\n      eligible_for_bounty: $eligibleForBounty\n      min_severity_score: $minSeverityScore\n      asm_tag_ids: $asmTagIds\n      asset_types: $assetTypes\n      from: $from\n      size: $size\n      sort: $sort\n    ) {\n      nodes {\n        ... on StructuredScopeDocument {\n          id\n          ...PolicyScopeStructuredScopeDocument\n          __typename\n        }\n        __typename\n      }\n      pageInfo {\n        startCursor\n        hasPreviousPage\n        endCursor\n        hasNextPage\n        __typename\n      }\n      total_count\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment PolicyScopeStructuredScopeDocument on StructuredScopeDocument {\n  id\n  identifier\n  display_name\n  instruction\n  cvss_score\n  eligible_for_bounty\n  eligible_for_submission\n  asm_system_tags\n  created_at\n  updated_at\n  total_resolved_reports\n  attachments {\n    id\n    file_name\n    file_size\n    content_type\n    expiring_url\n    __typename\n  }\n  __typename\n}\n",
            }
            self.log.info(
                f"Scraping scope and bounty data of program {program_handle}"
            )

            try:
                response = self.session.post(
                    "https://hackerone.com/graphql",
                    json=json_data,
                    proxies=self.proxies,
                    timeout=30,
                )
            except RequestException as e:
                self.log.error(
                    f"Error while scraping scope & bounties of program {program_handle}: {e}"
                )
                self.log.error(traceback.format_exc())
                return

            time.sleep(0.1)
            if response.status_code != 200:
                self.log.error(
                    f"Error while scraping scope & bounties of program {program_handle} "
                    f"(status={response.status_code})"
                )
                self.log.debug(f"Raw response (truncated): {response.text[:1000]}")
                return

            try:
                result = response.json()
            except ValueError:
                self.log.error(
                    f"Non-JSON response while scraping scope & bounties of "
                    f"program {program_handle}"
                )
                self.log.debug(f"Raw response (truncated): {response.text[:1000]}")
                return

            data = result.get("data")
            if not data or not data.get("team"):
                self.log.warning(
                    f"No data.team in scope & bounty response for {program_handle}"
                )
                return

            nodes = data["team"]["structured_scopes_search"]["nodes"]
            nodes = sort_data(nodes, "created_at")

            for edge in nodes:
                changeData = edge
                scope = changeData["identifier"]
                inScope = changeData["eligible_for_submission"]
                bountyEligible = changeData["eligible_for_bounty"]
                maxSeverity = changeData["cvss_score"]
                createdAt = changeData["created_at"]
                desc = changeData["instruction"]
                origin_id = changeData["id"]

                db_scope = Scope(
                    originId=origin_id,
                    source=SOURCE,
                    programHandle=program_handle,
                    scope=scope,
                    type="",
                    inScope=inScope,
                    bounties=bountyEligible,
                    maxSeverity=maxSeverity,
                    date=createdAt,
                    desc=desc,
                    data=json.dumps(changeData),
                )
                self.db_session.add(db_scope)
                self._safe_commit("scope and bounty")

        except Exception:
            self.log.error(
                f"Exception caught in scrape_scope_and_bounty\n{traceback.format_exc()}"
            )

    # program metadata + backup
    def parse_program(self, program):
        try:
            print(program)
            self.log.info(f"Currently parsing program: {program['name']}")
            pid = program["id"]
            name = program["name"]
            handle = program["handle"]
            state = program["state"]
            currency = program["currency"]
            number_resolved_reports = program["resolved_report_count"]
            launched_at = program["launched_at"]
            triage_active = program["triage_active"]

            # Changed fields - New:
            offers_bounties = program["offers_bounties"]
            min_reward = program["minimum_bounty_table_value"]
            max_reward = program["maximum_bounty_table_value"]

            # always insert program snapshot
            db_program = Program(
                source=SOURCE,
                programId=pid,
                handle=handle,
                companyName=name,
                state=state,
                bugCountValid=number_resolved_reports,
                launchedAt=launched_at,
                minReward=min_reward,
                maxReward=max_reward,
                currency=currency,
                triageActive=triage_active,
            )
            self.db_session.add(db_program)
            self._safe_commit("program insert")

            db_backup = Backup(
                source=SOURCE,
                type="program",
                identifier=f"{handle}",
                date=str(date.today()),
                data=json.dumps(program),
            )
            self.db_session.add(db_backup)
            self._safe_commit("program backup")

        except Exception:
            self.log.error(f"Exception caught in parse_program\n{traceback.format_exc()}")

    # main entry point
    def run(self):
        self.log.info("---- HackerOneScrapper started ----")
        self.teleBot.info("HackerOneScrapper started")

        self.teleBot.info("Login...")
        self.login()

        self.teleBot.info("Scraping programs...")
        self.scrape_programs()

        self.log.info("---- HackerOneScrapper finished ----")
        self.teleBot.info("HackerOne finished")
