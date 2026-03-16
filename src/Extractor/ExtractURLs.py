import re
import os
import shutil
import csv
import subprocess
import time
import tldextract
import threading
import BBScrapper.model
import PublicListScrappers.model.BugBountyTargets_model
import PublicListScrappers.model.FireBounty_model
import PublicListScrappers.model.ProjectDiscovery_model
import Collectors.model.CollectedData_model
import pandas as pd
import requests
import concurrent
import random
import dns.resolver
import openai
import json
import multiprocessing
import sqlite3

from pathlib import Path
from playwright.sync_api import sync_playwright
from playwright.sync_api import TimeoutError, Error as PlaywrightError
from sqlalchemy import create_engine, Column, Integer, String, Boolean, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(f'{BASE_DIR}/.env')

CHATGPT_API_KEY = os.getenv('CHATGPT_API_KEY')


EXTRACTOR_PROMPT_ORG = """
###Question: Do we have limits for requests per second? Do we have a Header which should be set while testing? ###Instruction: You are a text processor assistant. Always return a valid JSON String. Check if the text specifies a limit of requests per seonds, and if so add it to the returned json in key 'req_per_sec' as integer, if not that the field should be set to None. In addition, if there are requirements regarding a header which should be added/send along the requests, specify the header in the json at key 'headers'. Then there should be a json which has the Header Name as key and the value which should get set as value. If no Header Name is specified, use 'User-Agent' as standard. If {Username}, Mail-Alias or similiar should be set in one of the header values, replace it with USERNAME ###InputData: A long text and description of the rules. ###Output-Data: {'headers': {'User-Agent': 'BugBounty'}, 'req_per_sec': 4}} 
"""

EXTRACTOR_PROMPT = """
You are an information extraction system.
You do NOT summarize. You do NOT explain.

Return ONLY valid JSON.

Extract from the policy text:
1) request rate limits
2) required custom HTTP headers

-------------------------------
RATE LIMIT
-------------------------------
Only extract a numeric limit if explicitly measurable.

Examples to extract:
"5 requests per second"
"60 requests per minute"
"3600 per hour"

Convert to requests per second (integer):
60/min -> 1
120/min -> 2
3600/hour -> 1

If vague wording like:
"avoid aggressive traffic"
"be reasonable"
"no automated scanning"

then:
"req_per_sec": null

-------------------------------
HEADERS
-------------------------------
Extract ONLY headers the researcher MUST manually set.

Valid:
X-Bugcrowd: researcher
X-HackerOne: researcher

IGNORE:
- curl examples
- code snippets
- OAuth examples
- normal browser headers (User-Agent, Accept, Host, Connection)

-------------------------------
OUTPUT FORMAT
-------------------------------
{
  "req_per_sec": integer or null,
  "headers": { "Header": "Value" } or null
}

No extra keys.
"""

BASE_DIR = Path(__file__).resolve().parents[2]


USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/115.0.0.0 Safari/537.36",

    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/115.0",

    # Safari on iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15"
    " (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",

    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/115.0.0.0 Mobile Safari/537.36",

    # Opera on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/115.0.0.0 Safari/537.36 OPR/101.0.0.0",
]

def is_real_wildcard(url):
        # ensure urlparse works even without scheme
        if "://" not in url:
            url = "http://" + url

        host = urlparse(url).netloc.lower()

        # echte wildcard-domain nur wenn sie am Anfang steht
        return host.startswith("*.")

def testUrlPlaywright(url, handle, source, key, logger, result_queue):
    time.sleep(random.uniform(0, 0.5))
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    parsed_url = urlparse(url.strip())
    if not parsed_url.scheme:
        url = "http://" + url

    elif parsed_url.scheme not in ["http", "https"]:  
        url = "http://" + parsed_url.netloc + parsed_url.path
    logger.debug(f" [*] Testing {url} via Playwrigtht...")

    max_tries = 3
    success = False
    last_exception = None
    reason = None
    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        for attempt in range(1, max_tries+1):
            page = browser.new_page()
            page.set_extra_http_headers(headers)
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                if response is not None and response.status == 200:
                    current_url = page.url
                    # check if we got redirected
                    if accpeted_redirect(current_url, url):
                        html_content = page.content()
                        if "<html" in html_content.lower():
                            valid = True
                            success = True
                            break
                        else:
                            valid = False
                            reason = "No HTML tag found"
                            success = True
                            break
                    else:
                        valid = False
                        reason = f"Redirect to: {current_url}"
                        success = True
                        break
                else:
                    valid = False
                    reason = f"Status {response.status if response else 'No response'}"
            except Exception as e:
                last_exception = e
                valid = False
            finally:
                page.close()
            time.sleep(0.5)
        browser.close()

    if not success and last_exception is not None:
        reason = str(last_exception)

    result_queue.put((url, handle, source, key, valid, reason))

def deleteDirContent(dir):
    # Check if the directory exists
    if not os.path.exists(dir):
        return
    
    # Remove the entire directory and its contents
    try:
        shutil.rmtree(dir)
    except Exception as e:
        pass

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def has_dns_record(domain):
    # Try to get an A entry (IP) to the domains/subdomains to prefilter
    try:
        answers = dns.resolver.resolve(domain, 'A') 
        return len(answers) > 0
    except Exception:
        return False

def accpeted_redirect(original_url, redirected_url, page_change_allowed=True):
    def normalize_domain(url):
        url = url.replace("https://", "")
        url = url.replace("http://", "")
        url = url.replace("www.", "")

        extracted = tldextract.extract(url)
        # print("Orignal URL: {url}\nNormalized URL: {extracted.subdomain}{extracted.domain}.{extracted.suffix}")
        return f"{extracted.subdomain}{extracted.domain}.{extracted.suffix}"
    
    # Check if domain is the same (ignoring 'www')
    if normalize_domain(original_url) != normalize_domain(redirected_url):
        return False
    
    # Check if path is the same
    if not page_change_allowed:
        original_parsed = urlparse(original_url)
        redirected_parsed = urlparse(redirected_url)
        if original_parsed.path != redirected_parsed.path:
            return False

    # If domain and path are the same, then it's an acceptable redirect (only protocol or www change)
    return True

class UrlExtractor:
    def __init__(self, logger, teleBot) -> None:
        self.log = logger
        self.teleBot = teleBot

    def filterUrls(self, row):
        filtered_urls = []

        try:
            # Regular expression to match URLs 
            url_pattern = re.compile(
                r'(?i)\b(?:https?://|http://|www\.|\*\.)?'  # Matches http, https, www, or *.
                r'(?:[a-z0-9-]+\.)*\*?'                    # Matches subdomains and optional wildcard (*).
                r'[a-z0-9-]+'                              # Matches the main domain.
                r'(\.\*|(?:\.[a-z0-9-]+)+)'                # Matches TLDs like .com, .*, or wildcards in middle segments like shop.*.be.
                r'(:\d+)?'                                 # Matches optional port numbers.
                r'(/.*)?'                                  # Matches paths, including wildcards like /*.
            )

            valid_urls = []
            scope_entry = row.scope
            # Find all URLs in the entry
            urls = [match.group() for match in url_pattern.finditer(scope_entry)]
            valid_urls.extend(urls)

            # Add filtering for apps and github: 
            for url in valid_urls:
                if "github.com" in url:
                    continue

                if "play.google.com/store/" in url:
                    continue
                
                if "apps.apple.com/" in url:
                    continue

                if "marketplace.atlassian" in url:
                    continue

                # check for schemes
                crafted_url = url
                if not "http://" in url and not "https://" in url:
                    crafted_url = "http://" + url

                # check for wildcards
                if "*." in crafted_url:
                    filtered_urls.append([crafted_url, row.programHandle])
                    crafted_url = crafted_url.replace("*.", "").strip()
                        
                filtered_urls.append([crafted_url, row.programHandle])
            
            return filtered_urls
        
        except Exception as e:
            self.log.error(f"[!] Exception during filtering/extracting URLs of colleted entries: {e}")
            return filtered_urls
    
    def extractBBUrls(self, inscope=True):
        # Query the database
        engine = create_engine(f"sqlite:////{BASE_DIR}/data/BugBountyData.sqlite")
        Session = sessionmaker(bind=engine)

        with Session() as session:
            rows = session.query(BBScrapper.model.Scope)\
                .filter(BBScrapper.model.Scope.inScope.is_(inscope)).all()

        filtered_urls = []
        for row in rows:
            filtered_urls.extend(self.filterUrls(row))

        return filtered_urls

    def extractFBUrls(self, inscope=True):
        engine = create_engine(f"sqlite:////{BASE_DIR}/data/FireBountyData.sqlite")
        Session = sessionmaker(bind=engine)

        with Session() as session:
            rows = session.query(PublicListScrappers.model.FireBounty_model.Scope)\
                .filter(PublicListScrappers.model.FireBounty_model.Scope.inScope.is_(inscope)).all()

        filtered_urls = []
        for row in rows:
            filtered_urls.extend(self.filterUrls(row))

        return filtered_urls

    def extractPDUrls(self, inscope=True):
        engine = create_engine(f"sqlite:////{BASE_DIR}/data/ProjectDiscovery.sqlite")
        Session = sessionmaker(bind=engine)

        with Session() as session:
            rows = session.query(PublicListScrappers.model.ProjectDiscovery_model.Scope)\
                .filter(PublicListScrappers.model.ProjectDiscovery_model.Scope.inScope.is_(inscope)).all()

        filtered_urls = []
        for row in rows:
            filtered_urls.extend(self.filterUrls(row))

        return filtered_urls

    def extractVDPUrls(self):
        # Extract Urls from programs hosted on different providers
        self.teleBot.info("[*] Extract URLs collected from Providers...")
        BBUrls = self.extractBBUrls()

        # Extract Urls from programs hosted on FireBounty
        self.teleBot.info("[*] Extract URLs collected from FireBounty...")
        FBUrls = self.extractFBUrls()

        # Extract Urls from programs hosted on Project Discovery
        self.teleBot.info("[*] Extract URLs collected from Project Discovery...")
        PDUrls = self.extractPDUrls()

        self.log.info(f'BB Extracted URLs: {len(list(set(tuple(item) for item in BBUrls)))}')
        self.teleBot.info(f'[*] Extracted: {len(list(set(tuple(item) for item in BBUrls)))} URLs from BBs')

        self.log.info(f'FB Extracted URLs: {len(list(set(tuple(item) for item in FBUrls)))}')
        self.teleBot.info(f'[*] Extracted: {len(list(set(tuple(item) for item in FBUrls)))} URLs from FireBounty')
        
        self.log.info(f'PD Extracted URLs: {len(list(set(tuple(item) for item in PDUrls)))}')
        self.teleBot.info(f'[*] Extracted: {len(list(set(tuple(item) for item in PDUrls)))} URLs from Project Discovery')

        all_urls = BBUrls
        unique_urls = list(set(tuple(item[0]) for item in all_urls))

        self.log.info(f'[*] Extracted: ({len(all_urls)}) {len(unique_urls)} (overall) unique URLs')
        self.teleBot.info(f'[*] Extracted: ({len(all_urls)}) {len(unique_urls)} (overall) unique URLs')

        # TODO: Here we could add other datasets, if we want to use it in subsequent collection
        all_urls = {"BB": BBUrls}

        data = [
            {
                "source": source,
                "program": program,
                "url": url,
            }
            for source, urls in all_urls.items()
            for url, program in urls
        ]

        df_base = pd.DataFrame(data)

        # -------- Start Preparations for Sudomain discovery -  extract wildcard entries + remove duplicated wildcards --------
        self.log.info("[*] Start resolving wildcards to subdomains..")
        df = df_base[df_base['url'].apply(is_real_wildcard)].copy()
        df['key'] =  df['url'] + "-" + df['program'] + "-" + df['source']
        df = df.drop_duplicates(subset='key', keep='first') 

    
        # -------- Recon subdomains to the wildcards -------------
        df_subdomains = self.reconSubdomainsDF(df)
        subdomains_found = len(df_subdomains)

        # Dump number of found subdomains
        self.log.info(f" [*] Discovered {subdomains_found} subdomains")


        # -------- Remove discovered Out-Of-Scope Subdomains --------
        self.log.info("[*] Removing the subdomains specified as out-of-scope..")
        df = self.removeOOSThreaded(df_subdomains)

        # Check how many subdomains were removed
        self.log.info(f"[*] From {subdomains_found} domain, {subdomains_found - len(df)} domains were removed as out-of-scope")


        # -------- Concat the orginal dataset and their discovered AND in-scope subdomains + Remove duplicates ---------
        complete_df = pd.concat([df, df_base], ignore_index=True)
        self.log.info(f"[*] This leads to overall {len(complete_df)} URL-Progam-Provider combinations including subdomains")
        complete_df['cleaned_url'] = complete_df['url'].replace(
            {
                "https://www.": "",
                "http://www.": "",
                "https://": "",
                "http://": "",
            }, 
            regex=True
        )
        complete_df['key'] =  complete_df['cleaned_url'] + "-" + complete_df['program'] + "-" + complete_df['source']
        complete_df = complete_df.drop_duplicates(subset='key', keep='first')     
        self.log.info(f"[*] This leads to overall unique {len(complete_df)} URL-Progam-Provider combinations including subdomains")

        # -------- Check if the targets + discovered subdomains respond to http requests -> e.g. is still valid WebService + reachable/online -------
        self.log.info(f"[*] Testing if {len(complete_df)} URLs respond to requests with a valid response code...")
        checked_df = self.testUrls(complete_df, "VDP")
        
        # -------- Printing results -----------
        self.log.info(f'BB Extracted URLs: {checked_df[checked_df['Valid'] == True & (checked_df['source'] == 'BB')].shape[0]}')
        self.teleBot.info(f'[*] Extracted: {checked_df[checked_df['Valid'] == True & (checked_df['source'] == 'BB')].shape[0]} valid URLs from BBs')

        overall = len(checked_df)
        df_redirects = checked_df[checked_df['Reason'].str.contains('Redirect to:', na=False)]
        self.log.info(f"[*] Done testing URLs. {len(df_redirects)}/{overall} URLs failed due to redirects!")

        df_html_content = checked_df[checked_df['Reason'].str.contains('No HTML tag found', na=False)]
        self.log.info(f"[*] Done testing URLs. {len(df_html_content)}/{overall} URLs failed due to non-HTML content!")

        checked_df = checked_df[checked_df['Valid'] == True]
        self.log.info(f"[*] Done testing URLs. {len(checked_df)}/{overall} URLs responed with valid response and content")

        #self.log.info(f'FB Extracted URLs: {checked_df[checked_df['Valid'] == True & (checked_df['source'] == 'FB')].shape[0]}')
        #self.teleBot.info(f'[*] Extracted: {checked_df[checked_df['Valid'] == True & (checked_df['source'] == 'FB')].shape[0]} valid URLs from FireBounty')
        
        #self.log.info(f'PD Extracted URLs: {checked_df[checked_df['Valid'] == True & (checked_df['source'] == 'PD')].shape[0]}')
        #self.teleBot.info(f'[*] Extracted: {checked_df[checked_df['Valid'] == True & (checked_df['source'] == 'PD')].shape[0]} valid URLs from Project Discovery')

        #self.log.info(f'[*] Extracted: ({checked_df[checked_df['Valid'] == True].shape[0]}) -  (overall) unique valid URLs')
        #self.teleBot.info(f'[*] Extracted: ({checked_df[checked_df['Valid'] == True].shape[0]}) -  (overall) unique valid URLs')

        #  ------ Store the InScope + Reachable URLs + Discovered Subdomains -------
        # Now generate DB entries:
        engine = create_engine(f'sqlite:///{BASE_DIR}/data/CollectedData.sqlite')
        Session = sessionmaker(bind=engine)
        session = Session()
           
        i = 0
        for _, row in checked_df.iterrows():
                url = row['url']
                program = row['program']
                key = row['source']
                try:
                    new_url = Collectors.model.CollectedData_model.Urls(
                        identifier=f"{url}-{program}-{key}",
                        url=url,
                        handle=program,
                        source=key,
                        base=True,
                    )

                    # Add the record to the session
                    session.add(new_url)

                    # Commit the transaction to save the entry to the database
                    session.commit()

                except Exception as e:
                    session.rollback()
                    i = i+1
                    self.log.debug(f'Error {url} - {program} - {key}')

        self.log.info(f'{i} Errors during writing data to db - see debug logs')

    def extractCruxUrls(self, limit=1000): 
        csv_file_path = f'{BASE_DIR}/data/crux.csv'

        # Now generate a CSV file and DB:
        engine = create_engine(f'sqlite:///{BASE_DIR}/data/CollectedData.sqlite')
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # ---------------------- Read all entries of the CruX ----------------
        df = pd.read_csv(csv_file_path)
        # Filter for top 10k
        df_10k = df[df['rank'] <= int(limit)]

        # Add random entries of other buckets as well
        df_50k = df[(df['rank'] > 10000) & (df['rank'] <= 50000)]
        df_100k = df[(df['rank'] > 50000) & (df['rank'] <= 100000)]
        df_500k = df[(df['rank'] > 100000) & (df['rank'] <= 500000)]
        df_1000k = df[df['rank'] > 500000]

        df_sample_50k = df_50k.sample(n=min(500, len(df_50k)), random_state=1)
        df_sample_100k = df_100k.sample(n=min(500, len(df_100k)), random_state=1)
        df_sample_500k = df_500k.sample(n=min(500, len(df_500k)), random_state=1)
        df_sample_1000k = df_1000k.sample(n=min(500, len(df_1000k)), random_state=1)

        # TODO: Remove later
        df = df_10k        
        #df = pd.concat([df_10k, df_sample_50k, df_sample_100k, df_sample_500k, df_sample_1000k], ignore_index=True)

        # ---------- Test the extracted URLs for DNS entries and valid responses ----------------
        self.log.info("[*] Testing if URLs respond to requests with a valid response code...")
        overall = len(df)
        df['program'] = 'Top-' + df['rank'].astype(str)
        df['url'] = df['origin']
        df['source'] = 'CRUX'    
        # create a key similiar to BB Keys
        df['key'] =  df['url'] + "-" + df['program'] + "-" + df['source']
        df = self.testUrls(df, "CRUX")
        
        #df.to_csv(f'{BASE_DIR}/data/reachable_CRUX-raw.csv', index=False)

        df_redirects = df[df['Reason'].str.contains('Redirect to:', na=False)]
        self.log.info(f"[*] Done testing URLs. {len(df_redirects)}/{overall} URLs failed due to redirects!")

        df_html_content = df[df['Reason'].str.contains('No HTML tag found', na=False)]
        self.log.info(f"[*] Done testing URLs. {len(df_html_content)}/{overall} URLs failed due to non-HTML content!")

        df = df[df['Valid'] == True]
        self.log.info(f"[*] Done testing URLs. {len(df)}/{overall} URLs responed with valid response and content")

        # Drop the Pandas DataFrame into a CSV
        df.to_csv(f'{BASE_DIR}/data/reachable_CRUX.csv', index=False)

        for row in df.itertuples(index=True, name='Pandas'):
            try:
                new_url = Collectors.model.CollectedData_model.Urls(
                            identifier=f"{row.url}-{row.program}-{row.source}",
                            url=row.url,
                            handle=row.program,
                            source=row.source,
                            base=True,
                        )

                # Add the record to the session
                session.add(new_url)

                # Commit the transaction to save the entry to the database
                session.commit()

            except Exception as e:
                    session.rollback()
                    self.log.debug(f'Error {row.url} - top-{row.program} - CRUX')
    
    def removeOOS(self, row, df_oos, compiled_patterns):
        # Check if for each row in df if df['url'] is in df_oos['url'] OR if it matches something like "*.evil.com" e.g. is a listed subdomain
        url = row.url
        # --> OOS since extra specified
        if url in df_oos['url'].values:
            self.log.info(f" [!] Matched OOS - URL ! - {url}")
            return False
        
        for cp in compiled_patterns:
            if cp.match(url):
                self.log.info(f" [!] Matched OOS - WILDCARD ! - {url} - {cp}")
                return False
        # Wildcard pattern check -> there are also *.evil.com in oos list
        
        return True

    def removeOOSThreaded(self, df, max_workers=20, chunksize=100):
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]

        oos_df = self.extractVDPUrlsOOS()

        wildcards_oos = oos_df[oos_df['url'].str.contains(r'\*\.', regex=True)]
        print(len(wildcards_oos))
        # REGEX prebuilden
        compiled_patterns = []
        for pat in wildcards_oos['url']:
            parsed = urlparse(pat)
            netloc = parsed.netloc
            path = parsed.path

            # We don't care atm about path widlcards
            if '*' in path:
                continue

            # Domain-Wildcard -> We are interested in these
            if '*.' in netloc:
                netloc = re.escape(netloc).replace('\\*\\.', '.*\\.')
            else:
                netloc = re.escape(netloc)

            escaped_path = re.escape(path)
            regex_pattern = f'^{netloc}{escaped_path}$'
            compiled_patterns.append(re.compile(regex_pattern))
            
        all_results = []
        for smaller_df in smaller_dfs:
            collected_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_row = {
                    executor.submit(self.removeOOS, row, oos_df, compiled_patterns): row
                    for row in smaller_df.itertuples(index=True, name="Pandas")
                }

                for future in concurrent.futures.as_completed(future_to_row):
                    row = future_to_row[future]
                    try:
                        result = future.result()
                        if result == True:
                            collected_results.append(row._asdict())

                    except Exception as e:
                        self.log.error(f"[!] Error removing OOS of {row.url}: {e}")

            all_results.extend(collected_results)

        if all_results:
            result_df = pd.DataFrame(all_results)
        else:
            result_df = pd.DataFrame()

        return result_df

    def reconSubdomainsDF(self, df, max_workers=20, chunksize=100):
        '''
        If used threaded, the requests are more likely to get blocked and therefore we will miss some subdomains - For now we used 1 Thread and wait longer .-. Also the timeout should potentially be increased - or a better tool used.
        '''
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        all_results = []
        for smaller_df in smaller_dfs:
            collected_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_row = {
                    executor.submit(self.reconSubdomains, row): row
                    for row in smaller_df.itertuples(index=True, name="Pandas")
                }
            
                for future in concurrent.futures.as_completed(future_to_row):
                    row = future_to_row[future]  
                    try:
                        results = future.result()
                        #self.log.info(f"[*] Completed testing {row.url}")
                        for result in results:
                            collected_results.append(result)

                    except Exception as e:
                        self.log.error(f"[!] Error collecting subdomains of {row.url}: {e}")
                        row_dict = row._asdict()  
                        collected_results.append(row_dict)

            all_results.extend(collected_results)

        result_df = pd.DataFrame(all_results)
        return result_df

    def reconSubdomains(self, row):
        '''
        This function uses the repo "sublist3r" to collect subdomains for wildcard-domains which are specified as in scope. To stay in-scope the function compares the discovered subdomains against the collected list of out-of-scope Domains as well. In addition this function already makes a test request (since there are often many invalid subdomains discovered)

        TODO: Check alternaives to find subdomains
        '''
        #
        file_path = f"{BASE_DIR}/data/sublist3r/{threading.get_ident()}.txt"
        if os.path.exists(file_path):
            os.remove(file_path)

        # the original row should still be added to new df
        row_dict = row._asdict()
        url = row_dict['url']
        print(url)
        new_rows = []

        if not "*." in url:
            new_rows = []
            self.log.info(" [*] No wildcard domain, skipping..")
            return new_rows


        if "://" not in url:
            url = "http://" + url

        host = urlparse(url).netloc.lower()

        if not host.startswith("*."):
            return new_rows

        domain = host[2:]
        print(domain)
        self.log.info(f" [*] Collecting subdomains for {domain} - of {url}")
        
        command = ['sublist3r', '-d', domain, '-o', file_path]

        try:
            subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                timeout=60
            )
        except Exception as e:
            self.log.error(f" [*] Proccess Error occurred while reconning {domain}: {e}") 

        # we do NOT trust sublist3r exit codes
        if not os.path.isfile(file_path):
            self.log.error(f" [!] Sublist3r produced no output file for {domain}")
            return new_rows

        if os.path.getsize(file_path) == 0:
            self.log.warning(f" [!] Sublist3r found no subdomains for {domain}")
            return new_rows

        self.log.info(f" [*] Processing discovered subdomains for {domain}")

        try:
            with open(file_path, "r") as file:
                for line in file:
                    sub = line.strip().lower()

                    # skip empty / garbage lines
                    if not sub:
                        continue

                    # normalize to real URL for later HTTP testing
                    if not sub.startswith("http"):
                        sub = "http://" + sub

                    new_row = row_dict.copy()
                    new_row['url'] = sub
                    new_rows.append(new_row)

                    print(f"  [*] Discovered Subdomain: {sub}")
                    self.log.debug(f"  [*] Discovered Subdomain: {sub}")
                
        except Exception as e:
            self.log.error(f"[!] Exception - Could not read the txt for {domain} - {e}")

            return new_rows

    def hasDNSRecord(self, row):
        """
        TRUE - An A record was found
        FALSE - No DNS Entry
        """

        url = row.url
        try:
            # remove the portential set protocol
            domain = url.replace("http://", "").replace("https://", "").rstrip("/")
            
            # Using DIG for DNS recon
            result = subprocess.run(
                ["dig", "+short", domain],
                capture_output=True, text=True
            )
            
            # We want to ignore those, which are not mathced to an IP
            lines = [l.strip() for l in result.stdout.split("\n") if l.strip() != ""]
            return len(lines) > 0

        except Exception as e:
            # In case of an error -> could not be found or was invalid
            return False
            
    def testUrls_old(self, df, source, max_workers=30, chunksize=30):
        # To make things easier we prefilterer here via DNS Entries - If no dns entry is set to an IP we dont test it further
        
        # shuffle once to avoid provider bias / overwhelm one domain
        df = df.sample(frac=1, random_state=1).reset_index(drop=True)

        # ---------- DNS PREFILTER ----------
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        all_results = []

        for smaller_df in smaller_dfs:
            smaller_df = smaller_df.copy()
            collected_results = []
            smaller_df["domain_clean"] = smaller_df["url"].apply(
                lambda x: x.replace("http://", "")
                        .replace("https://", "")
                        .rstrip("/")
            )            
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers * 2) as executor:
                future_to_row = {
                    executor.submit(self.hasDNSRecord, row): row
                    for row in smaller_df.itertuples(index=True, name="Pandas")
                }
            
                for future in concurrent.futures.as_completed(future_to_row):
                        row = future_to_row[future]
                        try:
                            result = future.result()
                            if result == True:
                                collected_results.append(row._asdict())

                        except Exception as e:
                            self.log.error(f"[!] Error of {row.url}: {e}")

            self.log.info(f"[*] Lenght of the DF (valid/overall): {len(collected_results)}/{chunksize}")
            all_results.extend(collected_results)


        dns_df = pd.DataFrame(all_results)
        self.log.info(f"[*] Overall DNS Filtering: {len(dns_df)}/{len(df)} have an IP Entry")

        # For better debugging
        dns_df.to_csv(f'{BASE_DIR}/data/extractor/test_urls_dns_{source}.csv', index=False)

        # ------------ Now filter via simple HTTP requests ---------------
        all_results = []
        smaller_dfs = [dns_df.iloc[i:i + chunksize] for i in range(0, len(dns_df), chunksize)]

        for smaller_df in smaller_dfs:
            os.makedirs(f'{BASE_DIR}/data/testing/', exist_ok=True)
            self.log.info(f" [*] Processing chunk of size {len(smaller_df)}")
            
            # Create result queue
            result_queue = multiprocessing.Queue()
            
            # Create processes
            procs = []
            for _, row in smaller_df.iterrows():
                p = multiprocessing.Process(target=testUrlPlaywright, args=(row['domain_clean'], row['program'], row['source'], row['key'] , self.log, result_queue))
                procs.append(p)
                p.start()
            
            # Timeout management
            TIMEOUT = 60
            start = time.time()
            
            while time.time() - start <= TIMEOUT:
                unfinished_procs = [p for p in procs if p.is_alive()]
                if not unfinished_procs:
                    self.log.debug("  [*] All subprocesses completed successfully before timeout!")
                    break
                for p in unfinished_procs:
                    p.join(timeout=0.1)
                time.sleep(0.1)
            else:
                self.log.error("  [!] At least one process timed out! Terminating remaining processes.")
                for p in procs:
                    p.terminate()
            
            # Ensure all processes are cleaned up
            for p in procs:
                p.join()
            
            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():
                url, handle, source, key, valid, reason = result_queue.get()
                self.log.debug(f"  [*] Completed testing for {url}")
                collected_results.append({"url": url, "program": handle, "source": source, "key": key, "Valid": valid, "Reason": reason})
            else:
                self.log.debug(f"  [*] Results Empty!")

            # Remove old stuff
            self.log.info(f"[*] Killing still existing remains...")
            try:
                subprocess.run("pkill Firefox", shell=True, check=True)
            except Exception as e:
                if e.returncode == 1:
                    self.log.info("[*] No Firefox processes were running.")

                else:
                    self.log.error(f"[!] Killing still existing remains failed. STOPPTING THEREFORE!")
                    exit()

            # Clear Directory
            deleteDirContent(f'{BASE_DIR}/data/testing/')


            count_valid_true = sum(1 for entry in collected_results if entry.get("Valid") == True)
            self.log.info(f" [*] Valid: {count_valid_true} from {len(collected_results)}")
            all_results.extend(collected_results)

        result_df = pd.DataFrame(all_results)
        result_df.to_csv(f'{BASE_DIR}/data/extractor/test_urls_request_{source}.csv')

        return result_df
    
    def testUrls(self, df, source, max_workers=30, chunksize=30):

        # shuffle once to avoid provider bias
        df = df.sample(frac=1, random_state=1).reset_index(drop=True)

        # ---------- DNS PREFILTER ----------
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        all_results = []

        for smaller_df in smaller_dfs:

            smaller_df = smaller_df.copy()
            collected_results = []

            smaller_df["domain_clean"] = smaller_df["url"].apply(
                lambda x: x.replace("http://", "")
                          .replace("https://", "")
                          .rstrip("/")
            )

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers * 2) as executor:
                future_to_row = {
                    executor.submit(self.hasDNSRecord, row): row
                    for row in smaller_df.itertuples(index=True, name="Pandas")
                }

                for future in concurrent.futures.as_completed(future_to_row):
                        row = future_to_row[future]
                        try:
                            result = future.result()
                            if result is True:
                                collected_results.append(row._asdict())

                        except Exception as e:
                            self.log.error(f"[!] DNS error {row.url}: {e}")

            self.log.info(f"[*] Length of the DF (valid/overall): {len(collected_results)}/{len(smaller_df)}")
            all_results.extend(collected_results)

        dns_df = pd.DataFrame(all_results)

        self.log.info(f"[*] Overall DNS Filtering: {len(dns_df)}/{len(df)} have an IP Entry")

        # store debug
        os.makedirs(f'{BASE_DIR}/data/extractor', exist_ok=True)
        dns_df.to_csv(f'{BASE_DIR}/data/extractor/test_urls_dns_{source}.csv', index=False)

        # reshuffle AFTER DNS to avoid chunk bias
        dns_df = dns_df.sample(frac=1, random_state=2).reset_index(drop=True)

        # ---------- PLAYWRIGHT/HTTP Request TEST ----------
        all_results = []
        smaller_dfs = [dns_df.iloc[i:i + chunksize] for i in range(0, len(dns_df), chunksize)]

        for smaller_df in smaller_dfs:

            os.makedirs(f'{BASE_DIR}/data/testing/', exist_ok=True)
            self.log.info(f" [*] Processing chunk of size {len(smaller_df)}")

            result_queue = multiprocessing.Queue()
            procs = []

            # track what MUST return
            expected_keys = set()

            for _, row in smaller_df.iterrows():

                expected_keys.add(row['key'])

                p = multiprocessing.Process(
                    target=testUrlPlaywright,
                    args=(row['domain_clean'], row['program'], row['source'], row['key'], self.log, result_queue)
                )
                procs.append(p)
                p.start()

            # ---- timeout handling ----
            TIMEOUT = 120
            start = time.time()

            while time.time() - start <= TIMEOUT:
                unfinished = [p for p in procs if p.is_alive()]
                if not unfinished:
                    break
                for p in unfinished:
                    p.join(timeout=0.2)
                time.sleep(0.2)

            # kill stuck browsers
            for p in procs:
                if p.is_alive():
                    self.log.warning(f"[!] Killing stuck process PID={p.pid}")
                    p.terminate()

            for p in procs:
                p.join()

            # ---- collect results ----
            collected_results = []
            received_keys = set()

            while not result_queue.empty():
                url, handle, src, key, valid, reason = result_queue.get()

                received_keys.add(key)

                collected_results.append({
                    "url": url,
                    "program": handle,
                    "source": src,
                    "key": key,
                    "Valid": valid,
                    "Reason": reason
                })

            # ---- Check for some where we do not receive a result ----
            missing = expected_keys - received_keys

            for key in missing:
                self.log.warning(f"[!] No result returned for {key}")

                collected_results.append({
                    "url": None,
                    "program": None,
                    "source": source,
                    "key": key,
                    "Valid": False,
                    "Reason": "PROCESS_NO_RESULT"
                })

            # cleanup
            try:
                subprocess.run("pkill -f playwright", shell=True)
            except Exception:
                pass

            deleteDirContent(f'{BASE_DIR}/data/testing/')

            count_valid_true = sum(1 for entry in collected_results if entry.get("Valid") is True)
            self.log.info(f" [*] Valid: {count_valid_true} from {len(collected_results)}")

            all_results.extend(collected_results)

        result_df = pd.DataFrame(all_results)

        result_df.to_csv(f'{BASE_DIR}/data/extractor/test_urls_request_{source}.csv', index=False)

        return result_df
    
    def extractVDPUrlsOOS(self):
        # Extract Urls from programs hosted on different providers
        self.teleBot.info("[*] Extract OOS URLs collected from Providers...")
        BBUrls = self.extractBBUrls(inscope=False)

        # Extract Urls from programs hosted on FireBounty
        self.teleBot.info("[*] Extract OOS URLs collected from FireBounty...")
        FBUrls = self.extractFBUrls(inscope=False)

        # Extract Urls from programs hosted on Project Discovery
        self.teleBot.info("[*] Extract OOS URLs collected from Project Discovery...")
        PDUrls = self.extractPDUrls(inscope=False)

        self.log.info(f'BB Extracted OOS URLs: {len(list(set(tuple(item) for item in BBUrls)))}')
        self.teleBot.info(f'[*] Extracted: {len(list(set(tuple(item) for item in BBUrls)))} OOS URLs from BBs')

        self.log.info(f'FB Extracted OOS URLs: {len(list(set(tuple(item) for item in FBUrls)))}')
        self.teleBot.info(f'[*] Extracted: {len(list(set(tuple(item) for item in FBUrls)))} OOS URLs from FireBounty')
        
        self.log.info(f'PD Extracted OOS URLs: {len(list(set(tuple(item) for item in PDUrls)))}')
        self.teleBot.info(f'[*] Extracted: {len(list(set(tuple(item) for item in PDUrls)))} OOS URLs from Project Discovery')

        all_urls = BBUrls + FBUrls + PDUrls
        unique_urls = list(set(tuple(item[0]) for item in all_urls))

        self.log.info(f'[*] Extracted: ({len(all_urls)}) {len(unique_urls)} (overall) unique OOS URLs')
        self.teleBot.info(f'[*] Extracted: ({len(all_urls)}) {len(unique_urls)} (overall) unique OOS URLs')

        all_urls = {"BB": BBUrls, "FB": FBUrls, "PD": PDUrls}

        data = [
            {
                "source": source,
                "program": program,
                "url": url,
            }
            for source, urls in all_urls.items()
            for url, program in urls
        ]
        df = pd.DataFrame(data)

        return df

    def queryChatGPTAPI(self, row, client):
        try:
            key = f"{row.programHandle or ''}-{row.companyHandle or ''}-{row.source or ''}"
            policy_text = row.rules

            if not policy_text or len(policy_text.strip()) < 20:
                return None

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": EXTRACTOR_PROMPT},
                    {"role": "user", "content": policy_text[:12000]}
                ],
                timeout=60
            )

            content = response.choices[0].message.content
            data = json.loads(content)
            print(f"[LLM] Parsed JSON for {key}: {data}")


            self.log.debug(f"LLM extraction for {row.programHandle}: {data}")

            return data

        except Exception as e:
            self.log.error(f"LLM extraction failed for {row.programHandle}: {e}")
            return None
           
    def extractHeadersAndReqLimits(self, llm_extraction=False):
        header_dict = {}
        req_limit_dict = {}
        known_keys = set()
        self.log.info("[*] Starting the extraction of headers for vulnerability assements...")

        engine = create_engine(f"sqlite:////{BASE_DIR}/data/BugBountyData.sqlite")
        Session = sessionmaker(bind=engine)

        # ---------- YWH ----------
        with Session() as session:
            rows = session.query(BBScrapper.model.Scope)\
                .filter(BBScrapper.model.Scope.headerExtension.isnot(None)).all()

        self.log.info("[*] Starting extraction via specific fields...")
        for row in rows:
            key = f"{row.programHandle or ''}-{row.companyHandle or ''}-{row.source or ''}"

            try:
                self.log.info(f" [*] Found speicifed header: User-Agent: {row.headerExtension} for {key}")
                header_dict.setdefault(key, {})['User-Agent'] = row.headerExtension
                known_keys.add(key)
            except Exception as e:
                self.log.debug(f"Header parse error: {e}")


        # ---------- INTIGRITI ----------
        df = pd.read_sql_query(
            text("SELECT * FROM rules WHERE source!='Huoxian' AND rules IS NOT NULL"),
            engine
        )

        df_inti = df[df['source'] == "Intigriti"]

        for _, row in df_inti.iterrows():

            key = f"{row.programHandle or ''}-{row.companyHandle or ''}-{row.source or ''}"

            try:
                formated_rules = json.loads(row['rules'])
            except Exception:
                self.log.debug(f"Invalid JSON rules for {key}")
                continue

            testing = (
                formated_rules.get('rule', {})
                .get('content', {})
                .get('content', {})
                .get('testingRequirements', {})
            )

            user_agent = testing.get('userAgent')
            header = testing.get('requestHeader')

            headers = {}

            if user_agent:
                ua = user_agent.lower().replace('user-agent:', '').strip()
                headers["User-Agent"] = ua
                self.log.info(f" [*] Found speicifed header: User-Agent: {ua} for {key}")

            if header:
                # support multiple headers
                for line in header.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()
                        self.log.info(f" [*] Found speicifed header: {k.strip()}: {v.strip()} for {key}")

            if headers:
                header_dict.setdefault(key, {}).update(headers)
                known_keys.add(key)

        print("Extracted via specific fields:")
        print(len(header_dict.keys()))
        for key, ext in header_dict.items():
            print(f"{key} --------- {ext}")


        # ---------- YWH, Intrigriti, BugCrowd, HackerOne ------------
        with Session() as session:
            rows = session.query(BBScrapper.model.Rule)\
                .filter(BBScrapper.model.Rule.rules.isnot(None)).all()

        # Setup ChatGPT API
        # Initialize the client
        client = openai.OpenAI(api_key=CHATGPT_API_KEY)


        if llm_extraction:
            self.log.info("[*] Starting extraction via ChatGPT API...")
            filtered_rows = []
            for row in rows:
                key = f"{(row.programHandle or '')}-{(row.companyHandle or '')}-{(row.source or '')}"
                if key in known_keys:
                    # we already have a specificly set header
                    continue 
                if row.rules is None:
                    continue
                else:
                    filtered_rows.append(row)

            random.shuffle(filtered_rows)
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_row = {
                        executor.submit(self.queryChatGPTAPI, row, client): row
                        for row in filtered_rows
                    }

                    for future in concurrent.futures.as_completed(future_to_row):
                        row = future_to_row[future]
                        key = f"{row.programHandle or ''}-{row.companyHandle or ''}-{row.source or ''}"

                        try:
                            data = future.result()
                            if not data:
                                continue

                            # ---------- Request Rate ----------
                            req = data.get("req_per_sec")
                            if isinstance(req, int) and req > 0:
                                req_limit_dict[key] = req

                            # ---------- Headers ----------
                            headers = data.get("headers")

                            if isinstance(headers, dict) and headers:
                                clean_headers = {}

                                for k, v in headers.items():
                                    if not k or not v:
                                        continue

                                    k = k.strip()
                                    v = v.strip()

                                    # remove hallucinated examples
                                    if "<" in v or "example" in v.lower():
                                        continue

                                    clean_headers[k] = v

                                if clean_headers:
                                    header_dict.setdefault(key, {}).update(clean_headers)
                                    self.log.info(f" [*] LLM extracted headers for {key}: {clean_headers}")

                        except Exception as e:
                            self.log.error(f"[!] Exception during processing {row.programHandle}: {e}")

        # Dump the extracted information 
        try:
            if llm_extraction:
                with open(f"{BASE_DIR}/data/headers_found.json", "w") as file:
                    json.dump(header_dict, file, indent=4)

                with open(f"{BASE_DIR}/data/request_limits_found.json", "w") as file:
                    json.dump(req_limit_dict, file, indent=4)

            self.log.info("[*] Successfully stored extracted headers and request limits.")

        except Exception as e:
            self.log.error(f"[!] Error writing JSON files: {e}")
        

        # Now try to find each domain being part of the scope to correlate with header
        df = pd.read_sql_query(
            text("SELECT * FROM scopes WHERE scope IS NOT NULL"),
            engine
        )

        self.log.info("[*] Starting extraction of scope for programs we collected headers...")
        scopes_and_header_df = pd.DataFrame(columns=["subdomain", "domain", "suffix", "header_key", "header_value"])

        for _, row in df.iterrows():
            key = f"{(row.programHandle or '')}-{(row.companyHandle or '')}-{(row.source or '')}"
            if key in header_dict.keys():
                for header_name, header_value in header_dict[key].items():
                    # print(f"Header found for program: {key} - scope: {row.scope}")
                    # Extract the domain and add list with the Headers
                    # -> Based on domain only as fallback (better we use a header too far then to less)
                    try:
                        extraction = tldextract.extract(row.scope)
                        # Exact entry
                        new_row = [
                            extraction.subdomain, 
                            extraction.domain, 
                            extraction.suffix, 
                            header_name,
                            header_value
                        ]
                        scopes_and_header_df.loc[len(scopes_and_header_df)] = new_row
                        # wildcard for subdomains
                        new_row = [
                            "*", 
                            extraction.domain, 
                            extraction.suffix,
                            header_name,
                            header_value
                        ]
                        scopes_and_header_df.loc[len(scopes_and_header_df)] = new_row
                        # wildcard for subdomains AND suffix
                        new_row = [
                            "*", 
                            extraction.domain, 
                            "*", 
                            header_name,
                            header_value
                        ]
                        scopes_and_header_df.loc[len(scopes_and_header_df)] = new_row
                    except Exception as e:
                        self.log.info(" [!] Not a valid URL scope")


        # For the proxy
        scopes_and_header_df.to_csv(f"{BASE_DIR}/data/headers_scopes_correlation.csv")

    def extractVulnTypes(self):
        # TODO: -> We did this in the analysis step since we restrict ourselves to XSS (not stored)
        pass

    def main(self):  
        # ----- Colelct and Setup the Header for our Proxy
        self.extractHeadersAndReqLimits(True)

        # ----- Collect vulnerability types -----
        self.extractVulnTypes()

        # ----- Extract URLS --------
        self.extractVDPUrls()
        self.extractCruxUrls()
