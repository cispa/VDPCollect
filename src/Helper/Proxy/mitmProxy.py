import csv
import json
import time
import sqlite3
import asyncio
import argparse
import tldextract
from collections import defaultdict, deque
from mitmproxy import http
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class HeaderInjectorRateLimiter:
    def __init__(self, db_path,):
        self.db_path = db_path
        self.domain_headers = self.load_domains_headers()
        self.request_timestamps = defaultdict(list)

    def load_domains_headers(self):
        domain_headers = {}

        # Connect to the database
        with open(self.db_path, "r", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            
            # Fetch all results and populate domain_headers dictionary
            for row in reader:
                domain = f"{row['subdomain']}.{row['domain']}.{row['suffix']}"
                domain_headers[domain] = {row['header_key']: row['header_value']}
        
        # Close the connection
        
        return domain_headers

    def add_headers(self, flow: http.HTTPFlow):
        flow.request.headers["x-contact"] = "bbpcrawler2023@gmail.com"
        #flow.request.headers["x-subject"] = "research"

        user_agent = ""
        if 'User-Agent' in flow.request.headers.keys():
            user_agent = flow.request.headers['User-Agent']
        elif 'user-agent' in flow.request.headers.keys():
            user_agent = flow.request.headers['user-agent']


        # Add our USERNAME into the header where needed
        user_agent.replace("username", "bbpcrawler2023")

        host = flow.request.pretty_host
        try:
            extract = tldextract.extract(host)
        except Exception:
            print(f"[*] LOG: ERROR: TLDExtract Failed - {host}")
            return

        sub = extract.subdomain
        dom = extract.domain
        suf = extract.suffix
        full_key = f"{sub}.{dom}.{suf}"
        domain_suf_key = f"*.{dom}.{suf}"
        domain_only_key = f"*.{dom}.*"

        if full_key in self.domain_headers:
            print(f"[*] LOG: INFO SUBDOMAIN + DOMAIN + SUFFIX matched - {sub + "." + dom + "." + suf}")
            headers_to_add = self.domain_headers[full_key]
            for key, value in headers_to_add.items():
                if 'user-agent' == key.lower():
                    flow.request.headers[key.lower()] = user_agent + " " + value
                else:
                    flow.request.headers[key.lower()] = value

            return

        if domain_suf_key in self.domain_headers:
            print(f"[*] LOG: INFO DOMAIN + SUFFIX found matched - {sub + "." + dom + "." + suf}")
            headers_to_add = self.domain_headers[domain_suf_key]
            for key, value in headers_to_add.items():
                if 'user-agent' == key.lower():
                    flow.request.headers[key.lower()] = user_agent + " " + value
                else:
                    flow.request.headers[key.lower()] = value
            return

        elif domain_only_key in self.domain_headers:
            print(f"[*] LOG: INFO: Domain matched - {sub + "." + dom + "." + suf}")
            headers_to_add = self.domain_headers[domain_only_key]
            for key, value in headers_to_add.items():
                if 'user-agent' == key.lower():
                    flow.request.headers[key.lower()] = user_agent + " " + value
                else:
                    flow.request.headers[key.lower()] = value
            return
        
        else:
            pass
            #print("NOTHING MATCHED")

    def request(self, flow: http.HTTPFlow)-> None:
        self.add_headers(flow)

addons=[
    HeaderInjectorRateLimiter(f"{BASE_DIR}/code/data/headers_scopes_correlation.csv")
]