import requests
import json
from PublicListScrappers.model.ProjectDiscovery_model import Program, Scope, DBSession
import hashlib

def generate_md5_hash(json_obj):
    json_str = json.dumps(json_obj, sort_keys=True)  # sort_keys ensures consistent hashing
    json_bytes = json_str.encode('utf-8')
    md5_hash = hashlib.md5(json_bytes).hexdigest()
    return md5_hash

class ProjectDiscoveryScrapper:
    def __init__(self, logger) -> None:
        self.db_session = DBSession()
        self.log = logger

    def collect(self):
        # URL of the JSON data
        url = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json"

        # Fetch the data from the URL
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            programs = data.get("programs", [])

            # Iterate through each program and print the relevant information
            for program in programs:
                name = program.get("name", "N/A")
                url = program.get("url", "N/A")
                domains = program.get("domains", [])

                md5hash = generate_md5_hash(program)

                # Create the program entry
                # Add to DB if not already contained
                db_program = self.db_session.query(Program).filter_by(
                    key=md5hash,
                    handle=name,
                    programURL=url
                ).first()

                if not db_program:
                    db_program = Program(
                            key=md5hash,
                            handle=name,
                            programURL=url)
                    
                    self.db_session.add(db_program)
                    self.db_session.commit()

                # Create the domain entries
                for domain in domains:
                    db_scope = self.db_session.query(Scope).filter_by(
                        programHandle=name,
                        inScope=True,
                        scope=domain
                    ).first()

                    if not db_scope:
                        db_scope = Scope(
                                key=f'{name}-{domain}',
                                programHandle=name,
                                inScope=True,
                                scope=domain)
                        
                        self.db_session.add(db_scope)
                        self.db_session.commit()
