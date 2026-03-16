import json
import hashlib
import requests
from PublicListScrappers.model.FireBounty_model import Program, Scope, DBSession


def generate_md5_hash(json_obj):
    json_str = json.dumps(json_obj, sort_keys=True)
    json_bytes = json_str.encode("utf-8")
    return hashlib.md5(json_bytes).hexdigest()


class FireBountyScrapper:
    def __init__(self, logger) -> None:
        self.db_session = DBSession()
        self.log = logger

    def collect(self):
        # fetch raw data from FireBounty
        url = "https://firebounty.com/api/v1/scope/all/url_only/"

        try:
            response = requests.get(url, timeout=600)
            response.raise_for_status()
        except requests.RequestException as e:
            self.log.error(f"[!] FireBounty request failed: {e}")
            return

        try:
            json_response = response.json()
        except ValueError as e:
            self.log.error(f"[!] FireBounty JSON decoding failed: {e}")
            return

        # iterate FireBounty programs and store in database
        for program_type, data in json_response.items():
            if program_type == "white_listed":
                continue

            for program in data:
                tag = program.get("tag")
                if tag not in ("CVD", "bounty"):
                    continue

                key = program.get("slug")
                name = program.get("name")
                url = program.get("firebounty_url", "N/A")
                domains = program.get("scopes") or {}

                db_program = (
                    self.db_session.query(Program)
                    .filter_by(
                        key=key,
                        handle=name,
                        tag=tag,
                        type=program_type,
                        programURL=url,
                    )
                    .first()
                )

                if not db_program:
                    db_program = Program(
                        key=key,
                        tag=tag,
                        handle=name,
                        type=program_type,
                        programURL=url,
                    )
                    self.db_session.add(db_program)
                    self.db_session.commit()

                in_scopes = domains.get("in_scopes", [])
                out_scopes = domains.get("out_of_scopes", [])

                for domain in in_scopes:
                    scope_key = f"{key}-{name}-{domain['scope']}"
                    db_scope = (
                        self.db_session.query(Scope)
                        .filter_by(
                            key=scope_key,
                            programHandle=name,
                            inScope=True,
                            type=domain["scope_type"],
                            scope=domain["scope"],
                        )
                        .first()
                    )

                    if not db_scope:
                        db_scope = Scope(
                            key=scope_key,
                            programHandle=name,
                            inScope=True,
                            type=domain["scope_type"],
                            scope=domain["scope"],
                        )
                        try:
                            self.db_session.add(db_scope)
                            self.db_session.commit()
                        except Exception as e:
                            self.db_session.rollback()
                            self.log.error(
                                f"[!] Exception during storing entry for {key}-{domain['scope']}: {e}"
                            )

                for domain in out_scopes:
                    scope_key = f"{key}-{name}-{domain['scope']}"
                    db_scope = (
                        self.db_session.query(Scope)
                        .filter_by(
                            key=scope_key,
                            programHandle=name,
                            inScope=False,
                            type=domain["scope_type"],
                            scope=domain["scope"],
                        )
                        .first()
                    )

                    if not db_scope:
                        db_scope = Scope(
                            key=scope_key,
                            programHandle=name,
                            inScope=False,
                            type=domain["scope_type"],
                            scope=domain["scope"],
                        )
                        try:
                            self.db_session.add(db_scope)
                            self.db_session.commit()
                        except Exception as e:
                            self.db_session.rollback()
                            self.log.error(
                                f"[!] Exception during storing entry for {key}-{domain['scope']}: {e}"
                            )
