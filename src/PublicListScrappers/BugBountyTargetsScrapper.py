import json
import hashlib
import requests
from requests import RequestException

from PublicListScrappers.model.BugBountyTargets_model import Program, Scope, DBSession


def generate_md5_hash(json_obj):
    json_str = json.dumps(json_obj, sort_keys=True)
    json_bytes = json_str.encode("utf-8")
    return hashlib.md5(json_bytes).hexdigest()


class BugBountyTargetsScrapper:
    def __init__(self, logger) -> None:
        self.db_session = DBSession()
        self.base_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/"
        self.log = logger

    # basic HTTP + JSON helper
    def _fetch_json(self, filename: str):
        url = self.base_url + filename
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
        except RequestException as e:
            self.log.error(f"[!] Request failed for {url}: {e}")
            return None

        try:
            return resp.json()
        except ValueError as e:
            self.log.error(f"[!] JSON decode failed for {url}: {e}")
            return None

    # shared DB helpers
    def _get_or_create_program(self, key: str, handle: str, source: str, program_url: str):
        db_program = (
            self.db_session.query(Program)
            .filter_by(
                key=key,
                handle=handle,
                source=source,
                programURL=program_url,
            )
            .first()
        )

        if not db_program:
            db_program = Program(
                key=key,
                handle=handle,
                source=source,
                programURL=program_url,
            )
            self.db_session.add(db_program)
            self.db_session.commit()

        return db_program

    def _get_or_create_scope(
        self,
        scope_key: str,
        program_handle: str,
        in_scope: bool,
        source: str,
        type_value: str,
        scope_value: str,
    ):
        db_scope = (
            self.db_session.query(Scope)
            .filter_by(
                key=scope_key,
                programHandle=program_handle,
                type=type_value,
                scope=scope_value,
            )
            .first()
        )

        if db_scope:
            return db_scope

        db_scope = Scope(
            key=scope_key,
            programHandle=program_handle,
            inScope=in_scope,
            source=source,
            type=type_value,
            scope=scope_value,
        )

        self.db_session.add(db_scope)
        self.db_session.commit()
        return db_scope

    # provider-specific collectors
    def collectBugCrowd(self):
        data = self._fetch_json("bugcrowd_data.json")
        if data is None:
            return

        for program in data:
            name = program.get("name", "N/A")
            url = program.get("url", "N/A")
            domains = program.get("targets", {}) or {}

            program_key = generate_md5_hash(program)
            self._get_or_create_program(program_key, name, "BUGC", url)

            in_scopes = domains.get("in_scope", [])
            out_scopes = domains.get("out_of_scope", [])

            for domain in in_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, True, "BUGC", scope_type, scope_value)

            for domain in out_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, False, "BUGC", scope_type, scope_value)

    def collectFederacy(self):
        data = self._fetch_json("federacy_data.json")
        if data is None:
            return

        for program in data:
            name = program.get("name", "N/A")
            url = program.get("url", "N/A")
            domains = program.get("targets", {}) or {}

            program_key = generate_md5_hash(program)
            self._get_or_create_program(program_key, name, "FED", url)

            in_scopes = domains.get("in_scope", [])
            out_scopes = domains.get("out_of_scope", [])

            for domain in in_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, True, "FED", scope_type, scope_value)

            for domain in out_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, False, "FED", scope_type, scope_value)

    def collectHackenproof(self):
        data = self._fetch_json("hackenproof_data.json")
        if data is None:
            return

        for program in data:
            name = program.get("slug", "N/A")
            url = program.get("url", "N/A")
            domains = program.get("targets", {}) or {}
            archived = program.get("archived", False)

            if archived:
                continue

            program_key = generate_md5_hash(program)
            self._get_or_create_program(program_key, name, "HPRO", url)

            in_scopes = domains.get("in_scope", [])
            out_scopes = domains.get("out_of_scope", [])

            for domain in in_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, True, "HPRO", scope_type, scope_value)

            for domain in out_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, False, "HPRO", scope_type, scope_value)

    def collectHackerOne(self):
        data = self._fetch_json("hackerone_data.json")
        if data is None:
            return

        for program in data:
            name = program.get("handle", "N/A")
            url = program.get("url", "N/A")
            domains = program.get("targets", {}) or {}
            archived = program.get("archived", False)

            if archived:
                continue

            program_key = generate_md5_hash(program)
            self._get_or_create_program(program_key, name, "HONE", url)

            in_scopes = domains.get("in_scope", [])
            out_scopes = domains.get("out_of_scope", [])

            for domain in in_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("asset_type", "N/A")
                scope_value = domain.get("asset_identifier", "N/A")
                self._get_or_create_scope(scope_key, name, True, "HONE", scope_type, scope_value)

            for domain in out_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("asset_type", "N/A")
                scope_value = domain.get("asset_identifier", "N/A")
                self._get_or_create_scope(scope_key, name, False, "HONE", scope_type, scope_value)

    def collectIntigriti(self):
        data = self._fetch_json("intigriti_data.json")
        if data is None:
            return

        for program in data:
            company_handle = program.get("company_handle", "N/A")
            program_name = program.get("name", "N/A")
            name = f"{company_handle}-{program_name}"
            url = program.get("url", "N/A")
            domains = program.get("targets", {}) or {}
            status = program.get("status", "Unknown")

            if status != "open":
                continue

            program_key = generate_md5_hash(program)
            self._get_or_create_program(program_key, name, "INTI", url)

            in_scopes = domains.get("in_scope", [])
            out_scopes = domains.get("out_of_scope", [])

            for domain in in_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("endpoint", "N/A")
                impact = domain.get("impact")

                in_scope_flag = impact != "Out of scope"
                self._get_or_create_scope(scope_key, name, in_scope_flag, "INTI", scope_type, scope_value)

            for domain in out_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("endpoint", "N/A")
                self._get_or_create_scope(scope_key, name, False, "INTI", scope_type, scope_value)

    def collectYesWeHack(self):
        data = self._fetch_json("yeswehack_data.json")
        if data is None:
            return

        for program in data:
            name = str(program.get("id", "N/A"))
            url = program.get("url", "N/A")
            domains = program.get("targets", {}) or {}
            archived = program.get("disabled", False)

            if archived:
                continue

            program_key = generate_md5_hash(program)
            self._get_or_create_program(program_key, name, "YWH", url)

            in_scopes = domains.get("in_scope", [])
            out_scopes = domains.get("out_of_scope", [])

            for domain in in_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, True, "YWH", scope_type, scope_value)

            for domain in out_scopes:
                scope_key = generate_md5_hash(domain)
                scope_type = domain.get("type", "N/A")
                scope_value = domain.get("target", "N/A")
                self._get_or_create_scope(scope_key, name, False, "YWH", scope_type, scope_value)

    def collect(self):
        # orchestrate all providers
        self.collectBugCrowd()
        self.collectFederacy()
        
        # Seems to be no longer supported:
        # self.collectHackenproof()
        
        self.collectHackerOne()
        self.collectIntigriti()
        self.collectYesWeHack()
