import concurrent
import os
import subprocess
import time
import json
import Collectors.model.CollectedData_model
import xmltodict
import tldextract
import tempfile
import requests
import json
import pandas as pd
import psycopg2 as pg
import random
import uuid 
import signal
import multiprocessing
import time
import faulthandler
import signal

faulthandler.enable()
faulthandler.register(signal.SIGUSR1.value)

from pathlib import Path
from bs4 import BeautifulSoup
from mozprofile import FirefoxProfile
from urllib.parse import urljoin
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy import create_engine, text, select, MetaData, Table, or_
from datetime import datetime
from urllib3.exceptions import MaxRetryError, NewConnectionError
from urllib.parse import urlparse, urljoin
import pandas as pd
import shutil
from playwright.sync_api import sync_playwright
from playwright.sync_api import TimeoutError, Error as PlaywrightError
import numpy as np

class SOURCES:
    SOURCE_BENIGN = 0
    SOURCE_LOCATION_HREF = 1
    SOURCE_LOCATION_PATHNAME = 2
    SOURCE_LOCATION_SEARCH = 3
    SOURCE_LOCATION_HASH = 4
    SOURCE_URL = 5
    SOURCE_DOCUMENT_URI = 6
    SOURCE_BASE_URI = 7
    SOURCE_COOKIE = 8
    SOURCE_REFERRER = 9
    SOURCE_DOMAIN = 10
    SOURCE_WINDOW_NAME = 11
    SOURCE_POSTMESSAGE = 12
    SOURCE_LOCAL_STORAGE = 13
    SOURCE_SESSION_STORAGE = 14
    SOURCE_UNKNOWN_15 = 15
    SOURCE_UNKNOWN = 255

GENERATE_EXPLOIT_FOR_SOURCES = [SOURCES.SOURCE_LOCATION_HREF, SOURCES.SOURCE_LOCATION_SEARCH,
                                SOURCES.SOURCE_LOCATION_HASH, SOURCES.SOURCE_URL, SOURCES.SOURCE_DOCUMENT_URI,
                                SOURCES.SOURCE_BASE_URI]
GENERATE_EXPLOIT_FOR_SOURCES += [SOURCES.SOURCE_COOKIE]
GENERATE_EXPLOIT_FOR_SOURCES += [SOURCES.SOURCE_LOCAL_STORAGE]
GENERATE_EXPLOIT_FOR_SOURCES += [SOURCES.SOURCE_SESSION_STORAGE]


BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(f'{BASE_DIR}/.env')
DB_USER = os.getenv('DB_USER_PG')
DB_PASS = os.getenv('DB_PASS_PG')
DB_HOST = os.getenv('DB_HOST_PG')
DB_PORT = os.getenv('DB_PORT_PG')
DB_NAME = os.getenv('DB_NAME_PG')


cookie_buttons_content = [
    "Accept Cookies", "I Accept", "Accept", "Agree", "I Agree", "Got it", "OK", "Allow", 
    "Accept All", "I Consent", "Enable Cookies", "Accept & Close", "Yes, I Agree", 
    "Understood", "Continue", "Accept and Proceed", "Allow Cookies", "I Understand", 
    "Confirm", "Accept Terms", "Yes", "Accept & Continue", "Accept All Cookies", 
    "Consent to Cookies", "Allow All", "Accept All & Continue", "Allow Selection", 
    "Accept Selections", "Allow Essential", "Accept Necessary", "Enable", 
    "Enable All Cookies", "Yes to Cookies", "Agree and Close", "Accept our Cookies", 
    "Agree to Terms", "Proceed", "Continue with Cookies", "Manage Preferences", 
    "Confirm & Accept", "Accept Cookies and Continue", "OK with Cookies", "Got it, Thanks", "aktzeptieren", "consent"
]
age_verification_buttons_content = [
    "Enter", "I am 18+", "Yes", "Continue", "Proceed", "Verify Age", "Confirm Age", 
    "I am over 18", "I am 21+", "I am of legal age", "I am old enough", "Enter Site", 
    "Confirm", "Access", "Verify", "I am 18 years old or older", "Continue to Site", 
    "Agree & Enter", "Yes, Enter", "Yes, I am 18+", "I am 18 years old", "Confirm and Enter", 
    "Enter Website", "Proceed to Site", "I confirm I am 18+", "Yes, I am old enough", 
    "I confirm I am 21+", "Enter as Adult", "I am of age", "Continue as Adult", 
    "Yes, let me in", "Enter Here", "Proceed as 18+", "Continue as 18+", 
    "I am 18 or older", "I am legally old enough", "I confirm my age", 
    "Access Website", "Verify your age", "Confirm you are 18+", "Enter Now", 
    "Enter and Confirm Age", "I am over legal age", "Continue with Age Verification", 
    "Yes, proceed", "Agree and Enter", "Yes, continue", "Confirm and Continue"
]

USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/115.0.0.0 Safari/537.36",

    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/115.0",

    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/115.0.0.0 Mobile Safari/537.36",
]

class RedirectDetectedError(Exception):
    """Custom exception for when a redirect is detected."""

def process_row(row):
    try:
        prep_finding = json.loads(row['finding'])
        for source in prep_finding["sources"][:20]:  # Limit to first 20 sources
            if (
                source["source"] in GENERATE_EXPLOIT_FOR_SOURCES
                and source["hasEscaping"] + source["hasEncodingURI"] + source["hasEncodingURIComponent"] == 0 and prep_finding['sink_id'] != -1
            ):
                return (row['url'], prep_finding)  # Keep only relevant findings
    except Exception as e:
        print(f"Error processing row: {e}")
    return None  # Skip invalid rows

def start_proxy_instances(num_instances, base_port, working_dir, log_dir):
    processes = []
    os.makedirs(log_dir, exist_ok=True)
    for i in range(num_instances):
        port = base_port + i
        log_file_path = os.path.join(log_dir, f"MiTMProxyLog{i+1}.log")
        log_file = open(log_file_path, 'w+')
        mitm_command = [
            'mitmdump',
            '--ssl-insecure',
            '--set', f'confdir={BASE_DIR}/src/Helper/Proxy/certs',
            '-s', 'mitmProxy.py',
            '-p', str(port)
        ]
        try:
            # Start the MiTM Proxy Tool instance
            process = subprocess.Popen(
                mitm_command,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=working_dir
            )
            print(f"[+] MiTM Proxy server instance {i+1} started successfully on port {port}.")
            processes.append((process, log_file))
        except Exception as e:
            print(f"[!] Exception occurred while starting the MiTM server/script instance {i+1}!: {e}")
    return processes

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def process_console_msg(filepath, msg):
    try:
        if "VULN_DATA:" in msg.text:
            parsed_msg = json.loads(msg.text.replace("VULN_DATA: ", ""))
            existing_data = []

            if os.path.exists(filepath):
                with open(filepath, 'r') as file:
                    try:
                        existing_data = json.load(file)
                        if not isinstance(existing_data, list):
                            raise ValueError("JSON file does not contain a list.")
                    except json.JSONDecodeError:
                        print("JSON DECODE ERROR")
                        pass
            else:
                pass

            existing_data.append(parsed_msg)

            with open(filepath, 'w') as file:
                json.dump(existing_data, file, indent=4)

    except json.JSONDecodeError:
        print(f"[!] Message is not valid JSON: {msg.text}")

    except Exception as e:
        print(f"[!] Exception during processing message: {e}")

def get_base_domain(url):
    """
    Extracts the base domain (e.g., example.com) from a URL.
    """
    extracted = tldextract.extract(url)
    return f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"

def is_valid_url(url, base_domain):
    """
    Ensure the URL is valid, belongs to the same base domain, and is not an irrelevant link like 
    anchors, mailto, javascript, or non-http links.
    """
    parsed_url = urlparse(url)
    # Extract base domain from parsed URL
    link_base_domain = get_base_domain(url)
    return (parsed_url.scheme in ["http", "https"] and  # Valid scheme
            base_domain == link_base_domain)

def accpeted_redirect(original_url, redirected_url, page_change_allowed=True):
    def normalize_domain(url):
        url = url.replace("https://", "")
        url = url.replace("http://", "")
        url = url.replace("www.", "")

        extracted = tldextract.extract(url)
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

def deleteDirContent(dir):
    # Check if the directory exists
    if not os.path.exists(dir):
        return
    
    # Remove the entire directory and its contents
    try:
        shutil.rmtree(dir)
    except Exception as e:
        pass

def delete_tmp_profiles(tmp_dir="/tmp"):
    # Check if the directory exists
    if not os.path.exists(tmp_dir):
        print(f"Directory {tmp_dir} does not exist.")
        return

    # Iterate over all files and directories in the specified directory
    for item in os.listdir(tmp_dir):
        item_path = os.path.join(tmp_dir, item)
        
        # check for name tmp... -> as used to create the profile dirs
        if os.path.isdir(item_path) and item.startswith("tmp"):
            try:
                # If it's a temporary Firefox profile directory, delete it
                shutil.rmtree(item_path)
                print(f"Deleted Firefox temporary profile directory: {item_path}")
            except Exception as e:
                print(f"Error deleting {item_path}: {e}")

# Alternative to ISDAC - but was not too successfull with the small subset of terms we specified
def accept_cookies_and_age_verification_playwright(page):
    # Combine all cookie and age verification buttons into one list
    all_button_texts = cookie_buttons_content + age_verification_buttons_content
    all_button_texts_lower = [text.lower() for text in all_button_texts]  # Make all strings lowercase

    # Get all buttons on the page
    buttons = page.locator('button, [role="button"]').all()  # Locate all button-like elements

    for button in buttons:
        try:
            # Check the button text case-insensitively
            button_text = button.inner_text().strip().lower()
            if any(keyword in button_text for keyword in all_button_texts_lower): 
                button.click(timeout=100, force=True)  
                #print(f"Clicked button containing text: {button_text}")
                return  
        except TimeoutError:
            pass 
        except Exception as e:
            print(f"Error while clicking button: {e}")

    #print("No matching buttons found.")

# ----------- FUNCTIONS TO COLLECT THE METRICS ---------------
def collectSubpages(url, handle, source, logger, result_queue, max_pages=10, max_depth=2):
        unwanted_extensions = [
            '.pdf', '.mp4', '.mp3', '.png', '.jpg', '.jpeg', '.gif',
            '.zip', '.rar', '.exe', '.svg', '.doc', '.docx', '.xls',
            '.xlsx', '.ppt', '.pptx', '.txt', '.json', '.xml', '.css',
            '.js', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot'
        ]

        # random sleep since many pages share ddos protections
        time.sleep(random.uniform(0, 1.5))

        logger.info(f"[*] Started collecting subpages for {url}")
        subpages = []
        visited = set()

        # Initial queue with the starting URL
        queue = [(url, 0)]
        visited.add(url)

        # Create a TMP Profile with the cert preinstalled and extensions
        try:    
            # Create a temporary directory for the new profile 
            original_profile_path = f'{BASE_DIR}/data/collector/additionalData/template.default-default'
            temp_dir = tempfile.mkdtemp()
            profile = FirefoxProfile(temp_dir)
            shutil.copytree(
                original_profile_path,
                temp_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('lock')
            )
            logger.debug(" [*] TMP Profile with Certificate Created ")

        except Exception as e:
            logger.error(f" [!] Exception occured during the creation of a tmp Firefox profile! {e}")
            result_queue.put((url, handle, source, subpages))
            time.sleep(1)
            os._exit(0)

        try:
            with sync_playwright() as p:
                # Launch browser in headless mode
                context = p.firefox.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=True, 
                    user_agent=get_random_user_agent(),
                    java_script_enabled=True)

                while queue and len(subpages) < max_pages:
                    current_url, depth = queue.pop(0)
                    if depth > max_depth:
                        continue

                    max_retires = 3
                    max_links_test = 30
                    links_tested = 0
                    stop = False
                    for attempt in range(max_retires):
                        try:
                            logger.info(f" [+] Navigating to {current_url} (Attempt {attempt + 1}/{max_retires})")
                            with context.new_page() as page:
                                visited.add(current_url)
                                base_domain = get_base_domain(current_url)
                                # prefilter some unwated stuff -> url endings
                                if any(current_url.lower().endswith(ext) for ext in unwanted_extensions):
                                    logger.info(f"  [INFO] Skipping {current_url} due to unwanted file extension.")
                                    stop = True
                                    break
                            
                                response = page.goto(current_url, timeout=30_000, wait_until="domcontentloaded")
                                page.wait_for_selector("body", timeout=10_000)
                                if response is None:
                                    raise Exception("No response received.")

                                
                                # Check if there was a redirection
                                res_status_code = response.status
                                actual_page = page.url
                                if not is_valid_url(actual_page.lower(), base_domain.lower()) or 300 <= res_status_code < 400:
                                    # -> We are not at the page (domain) we were before
                                    logger.info(f' [!] Seemingly Redirection occurend: From {current_url} to {actual_page}')
                                    stop = True
                                    break
                                else:
                                    logger.debug(f' [*] No Redirection occurend: From {current_url} to {actual_page}')
                                
                                # Test for content-type-header
                                content_type = response.headers.get("content-type", "").lower()
                                if "text/html" not in content_type:
                                    logger.info(f"  [INFO] Skipping {current_url} due to non-HTML Content-Type: {content_type}")
                                    stop = True
                                    break  

                                # Process page content
                                soup = BeautifulSoup(page.content(), "html.parser")
                                # Find all links on the page and process them
                                links = set()
                                for a_tag in soup.find_all("a", href=True):
                                    link = a_tag['href']
                                    full_link = urljoin(page.url, link)
                                    full_link = full_link.split("#")[0]
                                    full_link = full_link.split("?")[0]
                                    links.add(full_link)

                                if len(links) == 0:
                                    logger.info(f"  [INFO] No Link on {current_url} found")
                                    stop = True
                                    break

                                for full_link in links:
                                    # We add a limit of URLs which gets tested per webpage
                                    if links_tested >= max_links_test:
                                        stop = True
                                        break

                                    if full_link not in visited and is_valid_url(full_link, base_domain):
                                        time.sleep(0.5) 
                                        # test if the disovered URL is responding with HTML
                                        if any(full_link.lower().endswith(ext) for ext in unwanted_extensions):
                                            logger.info(f"  [INFO] Skipping discovered {full_link} due to unwanted file extension.")
                                            continue
                                            
                                        # using requests
                                        #response_discovered = requests.get(full_link, timeout=30, headers={'user-agent': #get_random_user_agent()}, allow_redirects=False)
                                        #res_status_code = response_discovered.status_code

                                        # using playwright
                                        links_tested += 1
                                        response_discovered = page.goto(full_link, timeout=30_000, wait_until='domcontentloaded')
                                        

                                        res_status_code = response_discovered.status 
                                        content_type = response_discovered.headers.get("content-type", "").lower()
                                        if res_status_code < 300 and "text/html" in content_type:
                                            subpages.append(full_link)
                                            queue.append((full_link, depth + 1))
                                            logger.info(f'Valid new subpage discovered: {full_link}')

                                        else:
                                            logger.info(f'Invalid new subpage discovered: {full_link} - SC: {res_status_code} - Content: {content_type}')


                                    # If we already have 10 links we do not need to further loop
                                    if len(subpages) >= max_pages:
                                        logger.info(f'10 Subpages discovered')
                                        stop = True
                                        break

                                # If we have less then 10 webpages -> no new attempts for this URL but use the next in the queue 
                                if len(subpages) < max_pages:
                                    logger.info(f'Done processing {current_url} - Currently {len(subpages)} found')
                                    stop = True
                                    break

                                time.sleep(0.3) 

                            # Check if we stop -> successfully checked this website already or Retry (in case of exception or similiar)
                            if stop:
                                logger.info(f'10 Subpages discovered or no Link found - Stopping attempts')
                                break

                        except TimeoutError as te:
                            if 'waiting for locator("body") to be visible' in f'{te}':
                                logger.error(f" [!] - [Timeout] Attempt {attempt + 1} failed for {current_url} - <BODY> not found")
                            else:
                                logger.error(f" [!] - [Timeout] Attempt {attempt + 1} failed for {current_url}: {te}")
                            if attempt == max_retires - 1:
                                raise 

                        except Exception as e:
                            logger.error(f" [!] - [Exception] Failed to fetch {current_url}: {e}")
                            break  

                context.close()

        except Exception as e:
            logger.error(f"[!] Exception during collecting links/subpages: {e}")
        
        finally:
            # Remove the tmp profile
            shutil.rmtree(temp_dir, ignore_errors=True)

        result_queue.put((url, handle, source, subpages))
        time.sleep(1)
        os._exit(0)

def collectLighthouse(url, handle, source, logger, proxies, result_queue):
    '''
    Used as part of the thesis - not part of the paper.
    This function tries to run the lighthouse audit against the webpages to gain insisghts into different metrics regarding the performance, security, accessiblity etc.
    '''

    data_file = f'{BASE_DIR}/data/lighthouse/{os.getpid()}-results.json'
    logger.debug(f' [*] Starting lighthouse for {url}')
    os.environ['REQUESTS_CA_BUNDLE'] = f'{BASE_DIR}/src/Helper/Proxy/certs/mitmproxy-ca-cert.pem'        
    try:
        # First check if the URL redirects to other domain/subdomain -> We dont want to scan it
        headers = {
            "user-agent": get_random_user_agent()
        }
        res = requests.get(url, headers=headers, timeout=10, proxies=proxies, allow_redirects=False)
        if res.status_code >= 300:
            if res.status_code in [301, 302, 303, 307, 308]:
                # Get the redirect URL from the Location header
                redirect_url = res.headers.get('Location')
                if accpeted_redirect(redirect_url, get_base_domain(url)):
                    logger.info(f" [*] Accept Redirection to same subdomain.domain.suffix {url} -> {redirect_url}")
                else:
                    # -> This will not yield useless information anyways, so we can skip the lighthouse scan
                    logger.error(f" [!] Non-Accept Redirection occured: {url} -> {redirect_url}")
                    error_data = {"error": f'Redirection or Error - StatusCode: {res.status_code}'}
                    with open(data_file, 'w') as f:
                        json.dump(error_data, f)
                    result_queue.put((url, handle, source, data_file))
                    time.sleep(1)
                    os._exit(0)
                

        # Run Lighthouse as subprocess
        result = subprocess.run([
            'lighthouse', url, 
            '--disable-full-page-screenshot', 
            '--ignore-certificate-errors',
            '--emulatedUserAgent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            '--output', 'json', 
            '--chrome-flags="--headless --no-sandbox"', 
            f'--output-path={data_file}'
            ], 
            capture_output=True,
            timeout=90,
            preexec_fn=os.setsid
            )
        
        # Check if the subprocess completed successfully
        if result.returncode != 0:
            error_data = {"error": f'Exception: {result.stdout.decode()} {result.stderr.decode()}'}
            with open(data_file, 'w') as f:
                json.dump(error_data, f)
            logger.error(f" [*] Error occurred while scanning {url}")

        else:
            logger.info(f" [*] Scan completed for {url}. Results saved to {data_file}")


    except Exception as e:
        error_data = {"error": f'Exception: {e}'}
        with open(data_file, 'w') as f:
            json.dump(error_data, f)
        logger.error(f" [*] Exception occurred while scanning {url} - {e}")

    result_queue.put((url, handle, source, data_file))
    time.sleep(1)
    os._exit(0)

def collectLibVulnData(url, handle, source, logger, result_queue):
        logger.info(f'[*] Starting LibVuln Data Collection for {url}')
        data_file = f'{BASE_DIR}/data/collector/retirejs/{os.getpid()}-results.json'

        scanned_entry = [{"scanned": datetime.now().isoformat()}]
        with open(data_file, "w") as file:
            json.dump(scanned_entry, file, indent=4)
        
        extension_path_1 = f'{BASE_DIR}/src/external/retirejs_modified_extension'
        extension_path_2 = f'{BASE_DIR}/data/collector/additionalData/ISDCAC'
        temp_dir = tempfile.mkdtemp()
        
        try:
            with sync_playwright() as p:
                # Launch browser in headless mode
                browser = p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=True,
                    args=[
                        "--headless=new",
                        "--disable-gpu",
                        f"--load-extension={extension_path_1},{extension_path_2}",
                        f"--disable-extensions-except={extension_path_1},{extension_path_2}",
                        "--no-sandbox",
                    ]
                )

                try:
                    page = browser.new_page()
                    page.on("console", lambda msg: process_console_msg(data_file, msg))
                    # Navigate to the URL
                    page.goto(url, wait_until="load", timeout=30_000) 

                    # Check if there was a redirection
                    actual_page = page.url
                    if not accpeted_redirect(url, actual_page):
                        raise Exception(f' [!] Seemingly Redirection occurend: From {url} to {actual_page}')

                except Exception as e:
                    logger.error(f"[!] Error navigating to {url}: {e}")
                    # append the error to the current json in file
                    scanned_entry.append({"error": str(e)})
                    with open(data_file, 'w') as file:
                        json.dump(scanned_entry, file, indent=4)
                    result_queue.put((url, handle, source, data_file))
                    time.sleep(1)
                    os._exit(0)

                # Wait until retirejs is finished analysing
                time.sleep(10)
                browser.close()

                result_queue.put((url, handle, source, data_file))
                time.sleep(1)
                os._exit(0)
        
        except Exception as e:
            logger.error(f"[!] Exception during scanning with retirejs extension for {url}: {e}")
            # append the error to the current json in file
            scanned_entry.append({"error": str(e)})
            with open(data_file, 'w') as file:
                json.dump(scanned_entry, file, indent=4)
            result_queue.put((url, handle, source, data_file))
            time.sleep(1)
            os._exit(0)

def collectCertificateData(url, handle, source, logger, result_queue):
        data_file = f'{BASE_DIR}/data/collector/sslscan/{os.getpid()}-results.json'
    
        # SSLScan takes the domain only (and port optionally)
        domain = url.replace("https://", "")
        domain = url.replace("http://", "")
        logger.info(f'[*] Scanning domain: {url}...')         

        
        # Run sslscan and save the results to the XML file
        try:
            result = subprocess.run(
                ["sslscan", f"--xml={data_file}", domain],
                capture_output=True,
                timeout=90
            )
            
            # Check if the subprocess completed successfully
            if result.returncode != 0:
                logger.error(f" [*] Error occurred while scanning {domain}. {result.stdout} - {result.stderr}")    
                with open(data_file, "w") as file:
                    json.dump({"error": f"Exception: {result.stdout} - {result.stderr}"}, file)

            else:
                logger.info(f" [*] Scan completed for {domain}. Results saved to {data_file}.")
                with open(data_file) as xml_file:
                    xml_data = xml_file.read()
                    parsed_xml = xmltodict.parse(xml_data)

                # now dump the data as json into file
                with open(data_file, "w") as file:
                    json.dump({'sslscan': parsed_xml}, file)

            result_queue.put((url, handle, source, data_file))
            time.sleep(1)
            os._exit(0)
                
        
        except Exception as e:
            logger.error(f" [*] Exception occurred while scanning {url}: {e}")
            with open(data_file, "w") as file:
                json.dump({"error": f"Exception: {e}"}, file)
            result_queue.put((url, handle, source, data_file))
            time.sleep(1)
            os._exit(0)

def collectCookieAndIncludes(url, handle, source, logger, result_queue):
    logger.info(f'[*] Collecting Cookies and External Includes for {url}')
    coll_cookies = []
    included_scripts = []
    dynamic_js_files = set()
    final_url = None
    data_file = f'{BASE_DIR}/data/collector/cookie_includes/{os.getpid()}-results.json'

    # Create a TMP Profile with the cert preinstalled and extensions
    try:
        original_profile_path = f'{BASE_DIR}/data/collector/additionalData/template.default-default'
        temp_dir = tempfile.mkdtemp()
        shutil.copytree(
            original_profile_path,
            temp_dir,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns('lock')
        )
        logger.debug(" [*] TMP Profile with Certificate Created ")

    except Exception as e:
        logger.error(f" [!] Exception occurred during the creation of a tmp Foxhound profile! {e}")
        json_data = {"cookies": [{"error": f"Exception: {e}"}], "included_scripts": [{"error": f"Exception: {e}"}]}
        with open(data_file, "w") as file:
            json.dump(json_data, file)
        result_queue.put((url, handle, source, final_url, data_file))
        time.sleep(1)
        os._exit(0)

    try:
        with sync_playwright() as p:
            proxy = {"server": "http://localhost:9090"}
            browser = p.firefox.launch_persistent_context(
                user_data_dir=temp_dir, headless=True, proxy=proxy
            )

            try:
                page = browser.new_page()
                browser.pages[0].close()

                # Register event listener **before navigation**
                def intercept_response(response):
                    try:
                        if "Content-Type" in response.headers and "javascript" in response.headers["Content-Type"] or response.url.endswith(".js"):
                            js_url = response.url
                            extracted_js = tldextract.extract(js_url)
                            extracted_url = tldextract.extract(url)

                            # Ensure it's a third-party JS
                            if extracted_url.domain != extracted_js.domain:
                                dynamic_js_files.add(js_url)
                                logger.info(f" [*] Detected dynamically loaded JS: {js_url}")

                    except Exception as e:
                        logger.error(f"[!] Error processing response: {e}")

                page.on("response", intercept_response) 

                # Navigate to the URL
                page.goto(url, wait_until="load", timeout=60_000)

                # Detect actual URL after redirects
                actual_page = page.url
                final_url = actual_page
                if not accpeted_redirect(url, actual_page):
                    raise Exception(f' [!] Seemingly Unwanted Redirection occurred: From {url} to {actual_page}')

            except Exception as e:
                logger.error(f"[!] Error navigating to {url}: {e}")
                json_data = {"cookies": [{"error": f"Exception: {e}"}], "included_scripts": [{"error": f"Exception: {e}"}]}
                with open(data_file, "w") as file:
                    json.dump(json_data, file)
                result_queue.put((url, handle, source, final_url, data_file))
                time.sleep(1)
                os._exit(0)

            time.sleep(2)

            # Extract static script tags
            script_urls = page.evaluate("""
                Array.from(document.querySelectorAll('script[src]')).map(script => script.src)
            """)

            extracted_url = tldextract.extract(url)
            for script_url in script_urls:
                extracted_source = tldextract.extract(script_url)
                if extracted_url.domain == extracted_source.domain:
                    continue
                if not script_url.startswith('http'):
                    script_url = urljoin(url, script_url)
                included_scripts.append(script_url)

            # Allow time for dynamic scripts to be intercepted
            time.sleep(5)

            # Collect cookies
            coll_cookies = browser.cookies()
            
            # Save results
            json_data = {
                "cookies": coll_cookies,
                "included_scripts": list(set(included_scripts + list(dynamic_js_files)))
            }
            with open(data_file, "w") as file:
                json.dump(json_data, file)
                
            result_queue.put((url, handle, source, final_url, data_file))
            time.sleep(1)
            os._exit(0)

    except Exception as e:
        logger.error(f"[!] Exception occurred during data collection for {url}: {e}")
        json_data = {"cookies": [{"error": f"Exception: {e}"}], "included_scripts": [{"error": f"Exception: {e}"}]}
        with open(data_file, "w") as file:
            json.dump(json_data, file)
        result_queue.put((url, handle, source, final_url, data_file))
        time.sleep(1)
        os._exit(0)

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def collectHeaders(url, handle, source, logger, proxies, result_queue):
    headers_dict = {"error": None, "data": None}
    csp_dict = {"error": None, "analysis": None, "location": None}
    logger.info(f'[*] Collecting Headers for {url}')
    data_file = f'{BASE_DIR}/data/collector/headers/{os.getpid()}-results.json'

    if url == "domain":
        return None
    
    headers = {
        "user-agent": get_random_user_agent()
    }

    try:
        # Send GET request to the URL
        if "https://" in url or "http://" in url:
            res = requests.get(url, headers=headers, timeout=30, proxies=proxies, allow_redirects=False)
        else:
            res = requests.get("https://" + url, headers=headers, timeout=30, proxies=proxies, allow_redirects=False)
    
    except MaxRetryError as e:
        logger.error(f" [!] Max retries exceeded for {url} - {e}")
        csp_dict["error"] = f"MaxRetryError: {str(e)}"
        headers_dict['error'] = f"MaxRetryError: {str(e)}"
        data = {'headers': headers_dict , 'evaluation': csp_dict}
        with open(data_file, "w") as file:
            json.dump(data, file)
        result_queue.put((url, handle, source,  data_file))
        time.sleep(1)
        return
    
    except NewConnectionError as e:
        logger.error(f" [!] Connection error for {url} - {e}")
        csp_dict["error"] = f"NewConnectionError: {str(e)}"
        headers_dict['error'] = f"NewConnectionError: {str(e)}"
        data = {'headers': headers_dict, 'evaluation': csp_dict}
        with open(data_file, "w") as file:
            json.dump(data, file, indent=4)
        result_queue.put((url, handle, source, data_file))
        time.sleep(1)
        return

    except Exception as e:
        logger.error(f' [!] Exception while collecting: {e}')
        csp_dict["error"] = f"Exception: {str(e)}"
        headers_dict['error'] = f"Exception: {str(e)}"
        data = {'headers': headers_dict, 'evaluation': csp_dict}
        with open(data_file, "w") as file:
            json.dump(data, file, indent=4)
        result_queue.put((url, handle, source, data_file))
        time.sleep(1)
        return

    if res.status_code >= 300:
        if res.status_code in [301, 302, 303, 307, 308]:
            # Get the redirect URL from the Location header
            redirect_url = res.headers.get('Location')
            if accpeted_redirect(redirect_url, get_base_domain(url)):
                logger.info(f" [*] Accept Redirection to same subdomain.domain.suffix {url} -> {redirect_url}")
            else:
                logger.error(f" [!] Status Code {res.status_code} for {url}")
                csp_dict["error"] = f"StatusCode: {res.status_code}"
                headers_dict['error'] = f"StatusCode: {res.status_code}"
                data = {'headers': headers_dict, 'evaluation': csp_dict}
                with open(data_file, "w") as file:
                    json.dump(data, file, indent=4)
                result_queue.put((url, handle, source, data_file))
                time.sleep(1)
                return

        else:
            logger.error(f" [!] Status Code {res.status_code} for {url}")
            csp_dict["error"] = f"StatusCode: {res.status_code}"
            headers_dict['error'] = f"StatusCode: {res.status_code}"
            data = {'headers': headers_dict, 'evaluation': csp_dict}
            with open(data_file, "w") as file:
                json.dump(data, file, indent=4)
            result_queue.put((url, handle, source, data_file))
            time.sleep(1)
            return

    # Let the tool analyze csp
    csp_location = "None"
    coll_headers = dict(res.headers)
    headers_dict['data'] = coll_headers
    lowercased_headers = {k.lower(): v for k, v in coll_headers.items()}
    csp_string = None
    
    # Check if Content-Security-Policy header exists
    if 'content-security-policy' in lowercased_headers:
        csp_location = "HEADER-STATIC"
        csp_string = lowercased_headers['content-security-policy']
    
    # Check if Content-Security-Policy is defined via Meta-Tag
    else:
        soup = BeautifulSoup(res.content, "html.parser")
        meta_csp = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})
        if meta_csp and 'content' in meta_csp.attrs:
            csp_string = meta_csp['content']
            csp_location = "META-STATIC"
    
    if csp_string:
        try:
            result = subprocess.run(
                ['node', f'{BASE_DIR}/data/collector/additionalData/csp_evaluator.mjs', csp_string],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                try:
                    csp_dict["analysis"] = json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    logger.error(f" [!] JSON Decode Error of results: {e}")
                    csp_dict["error"] = f"JSONDecodeError: {str(e)}"
                    csp_dict["location"] = csp_location
                    data = {'headers': headers_dict, 'evaluation': csp_dict}
                    with open(data_file, "w") as file:
                        json.dump(data, file, indent=4)
                    result_queue.put((url, handle, source, data_file))
                    time.sleep(1)
                    return

            else:
                logger.error(" [!] No output from subprocess csp-scan")
                csp_dict["error"] = "No output from subprocess csp-scan"
                csp_dict["location"] = csp_location
                data = {'headers': headers_dict, 'evaluation': csp_dict}
                with open(data_file, "w") as file:
                    json.dump(data, file, indent=4)
                result_queue.put((url, handle, source, data_file))
                time.sleep(1)
                return

        except Exception as e:
            logger.error(f" [!] Error during execution of csp evaluator: {e}")
            csp_dict["error"] = f"Exception during execution of csp evaluator: {str(e)}"
            csp_dict["location"] = csp_location
            data = {'headers': headers_dict, 'evaluation': csp_dict}
            with open(data_file, "w") as file:
                json.dump(data, file, indent=4)
            result_queue.put((url, handle, source, data_file))
            return

    else:
        logger.warning(f" [!] No Content-Security-Policy found for {url}")
        csp_dict["error"] = "No Content-Security-Policy found"
    
    csp_dict["location"] = csp_location
    data = {'headers': headers_dict, 'evaluation': csp_dict}
    with open(data_file, "w") as file:
        json.dump(data, file, indent=4)
    result_queue.put((url, handle, source, data_file))
    time.sleep(1)

def collectFlowData(url, logger):
    logger.info(f'[*] Collecting TaintFlows for {url}')
    foxhound_path = f'{BASE_DIR}/src/external/foxhound/foxhound'
    path_ext = f'{BASE_DIR}/data/collector/additionalData/foxhound_taints/extension/ext/ping_pong@example.org.xpi'
    extension_path_2 = f'{BASE_DIR}/src/external/istilldontcareaboutcookies-1.1.4.xpi'

    # Create a TMP Profile with the extension
    try:    
        # Create a temporary directory for the profile
        temp_dir = tempfile.mkdtemp()
        profile = FirefoxProfile(temp_dir)

        # Manually copy the .xpi file into the profile's extensions directory
        extensions_dir = os.path.join(temp_dir, "extensions")
        if not os.path.exists(extensions_dir):
            os.makedirs(extensions_dir)
        
        # First Extension
        extension_filename = os.path.basename(path_ext)
        destination = os.path.join(extensions_dir, extension_filename)
        shutil.copy(path_ext, destination)

        # Second Extension
        extension_filename = os.path.basename(extension_path_2)
        destination = os.path.join(extensions_dir, extension_filename)
        shutil.copy(extension_path_2, destination)


    except Exception as e:
        logger.error(f" [!] Exception occured during the creation of a tmp Foxhound profile! {e}")
    
    try:
        # Launch Playwright and create a persistent context
        with sync_playwright() as p:
            browser = p.firefox.launch_persistent_context(
                user_data_dir=temp_dir,
                headless=True,
                executable_path=foxhound_path,
                args=['--no-remote']
            )
        
            logger.debug(f" [*] Opening a new tab for: {url}")
            try:
                page = browser.new_page()
                browser.pages[0].close()
                # Navigate to the URL and log navigation status
                response = page.goto(url, wait_until="load", timeout=60_000) 

                # Check if there was a redirection
                res_status_code = response.status
                actual_page = page.url
                if not accpeted_redirect(url, actual_page):
                    # -> We are not at the page (domain) we were before
                    raise Exception(f' [!] Seemingly Redirection occurend: From {url} to {actual_page}')
            except Exception as e:
                logger.error(f" [!] Error navigating to {url}: {e}")

            
            # let foxhound extract and report flows
            time.sleep(10) 

            # TODO: Accept adult stuff and Cookie banners -> Still slow
            #accept_cookies_and_age_verification_playwright(page)

            # Just useful for debugging
            #page.screenshot(path="screenshot.png")

            # Perform actions on each page
            page.close()  
            browser.close()

    except Exception as e:
        logger.error(f' [!] Exception during taint collection via Foxhound: {e}')
    
    finally:
        # Delete the tmp profile directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def generateExploit(prep_finding, url, logger, result_queue):
        finding_id = prep_finding['finding_id']
        data_file = f'{BASE_DIR}/data/collector/findings/{os.getpid()}_generation_results.json'
        finding_path = f"{BASE_DIR}/data/collector/findings/finding-{os.getpid()}.json"
        output_path = f"{BASE_DIR}/data/collector/findings/output-{os.getpid()}.json"
        # This speeds-up since filtering happens earlier - otherwhise only in script
        usable = False
        for source in prep_finding["sources"][:20]:
            if (
                source["source"] in GENERATE_EXPLOIT_FOR_SOURCES and 
                source["hasEscaping"] + source["hasEncodingURI"] + source["hasEncodingURIComponent"] == 0
            ):
                usable = True
                break
                
        if not usable:
            logger.error(f" [:(] No usable output - Prefiltered") 
            result_queue.put((url, None))
            time.sleep(5)
            os._exit(0)

        logger.info(f" [*] Starting Explot Gerneration for (usable) Finding with ID {finding_id}")
        error = ""
        try:
            # Write the finding to the JSON file
            with open(finding_path, 'w') as f:
                json.dump(prep_finding, f, indent=4)
        
            # Command to execute the subprocess
            PY2 = f"{BASE_DIR}/masterenv_python2/bin/python2.7"
            SCRIPT = f"{BASE_DIR}/src/external/persistent-clientside-xss-for-login-security/src/main_filearg.py"

            command = [
                PY2,
                SCRIPT,
                "-f", finding_path,
                "-o", output_path
            ]

            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600
            )

            output = result.stdout.strip() + result.stderr.strip()
            logger.info(output)
            # Check for specific output conditions -> If results is printed and non empty the output file should be checked
            if "[result][" in output and not "[result][]" in output:
                    logger.info(f" [*] Generated exploit for: {url}") 
                    try:
                        # verify its valid JSON
                        with open(output_path, "r") as file:
                            content = file.read()
                            data = json.loads(content)
                            # Double encoded?
                            if isinstance(data, str):
                                data = json.loads(data)
                            exploit_data = data[0]
                            with open(data_file, "w") as out_file:
                                exploit_data['url'] = url
                                json.dump(exploit_data, out_file)
                            result_queue.put((url, data_file))
                            time.sleep(5)
                            os._exit(0)
    
                    except Exception as e:
                        logger.error(f" [!] Exception during reading generated exploit: {e}") 
                        result_queue.put((url, None))
                        time.sleep(5)
                        os._exit(0)
            else:
                logger.error(f" [:(] No usable output") 
                result_queue.put((url, None))
                time.sleep(5)
                os._exit(0)

            if result.stderr:
                logger.error(f" [!] Subprocess errors for finding {finding_id}:\n{result.stderr}")
                result_queue.put((url, None))
                os._exit(0)

        except Exception as e:
            logger.error(f" [!] Exception during subprocess execution for finding {finding_id}: {e} {output}")
            result_queue.put((url, None))
            os._exit(0)

def testExploit(ExplGenResult, org_url, logger, result_queue):
    # if exploit_url -> RCXXS, else storage/cookie etc based -> PCXSS -> use original URL
    data_file = f'{BASE_DIR}/data/collector/findings/{os.getpid()}_validation_results.json'
    results = []

    # Determine target URLs -> debending on the type of exploit
    exploit_urls = []
    if "exploit_url" in ExplGenResult:
        exploit_urls = ExplGenResult["exploit_url"]
    else:
        exploit_urls.append(org_url)

    extension_path = f'{BASE_DIR}/src/external/istilldontcareaboutcookies-1.1.4.xpi'

    for expl_url in exploit_urls:
        result = {
            "exploit_details": ExplGenResult,
            "org_url": org_url,
            "used_url": expl_url,
            "validated": False
        }
        try:
            # Create a temp profile with the extension
            temp_dir = tempfile.mkdtemp()
            profile = FirefoxProfile(temp_dir)

            extensions_dir = os.path.join(temp_dir, "extensions")
            os.makedirs(extensions_dir, exist_ok=True)
            shutil.copy(extension_path, os.path.join(extensions_dir, os.path.basename(extension_path)))

            with sync_playwright() as p:
                browser = p.firefox.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=True,
                    args=['--no-remote']
                )

                logger.debug(f"[*] Opening a new tab for: {expl_url}")
                page = browser.new_page()
                browser.pages[0].close()

                state = {"alert_detected": False}

                def handle_dialog(dialog):
                    msg = dialog.message
                    logger.debug(f"[!] Alert dialog detected: '{msg}'")
                    state["alert_detected"] = True
                    state["alert_message"] = msg
                    dialog.accept()

                page.on("dialog", handle_dialog)

                # Setup storage/cookie
                if "replace_with" in ExplGenResult:
                    key = json.dumps(ExplGenResult["storage_key"])
                    value = json.dumps(ExplGenResult["replace_with"])
                    stype = ExplGenResult.get("storage_type", "")

                    if stype == "localStorage.getItem":
                        page.add_init_script(f'localStorage.setItem({key}, {value});')
                    elif stype == "sessionStorage.getItem":
                        page.add_init_script(f'sessionStorage.setItem({key}, {value});')
                    elif stype == "document.cookie":
                        browser.add_cookies([{
                            "name": ExplGenResult["storage_key"],
                            "value": ExplGenResult["replace_with"],
                            "url": expl_url,
                        }])

                # Visit and test
                page.goto("about:blank")
                page.goto(expl_url, timeout=60_000)
                time.sleep(10)

                try:
                    current_domain = page.evaluate("() => document.domain")
                    state["current_domain"] = current_domain
                except Exception as eval_error:
                    logger.warning(f"[!] Could not get document.domain: {eval_error}")
                    state["current_domain"] = None

                browser.close()

                if state["alert_detected"]:
                    alert_msg = state.get("alert_message", "")
                    domain = state.get("current_domain", "")
                    
                    if domain and domain in alert_msg:
                        logger.info(f"[*] SUCCESS: Alert contains correct domain '{domain}' - {expl_url} - AlertContent: {alert_msg}")
                        result["validated"] = True
                    else:
                        logger.warning(f"[!] Alert triggered, but domain mismatch. Domain: '{domain}', Alert: '{alert_msg}'")
                        result["validated"] = False
                    
                    result["alert_message"] = alert_msg
                    result["document_domain"] = domain
                    results.append(result)

        except Exception as e:
            logger.error(f"[!] Exception occurred while testing {expl_url}: {e}")
            result["validated"] = False
            results.append(result)
            continue  # Try next URL if one fails

    # Write results once all URLs tested (or one succeeded)
    with open(data_file, "w") as file:
        json.dump(results, file)
    result_queue.put((org_url, data_file))
    time.sleep(5)
    os._exit(0)

class Collector:
    def __init__(self, logger, teleBot) -> None:
        self.log = logger
        self.teleBot = teleBot        

        engine = create_engine(f'sqlite:///{BASE_DIR}/data/CollectedData.sqlite')
        Session = sessionmaker(bind=engine)
        self.session_urls = Session()
        self.proxies = []

    def get_proxies(self):  
        return random.choice(self.proxies)

    def readDataFromDB(self):
        query = text("SELECT * FROM urls")
        result = self.session_urls.execute(query)
        df = pd.DataFrame(result.fetchall(), columns=result.keys())
        return df
    
    def collectHeadersMultiProcess(self, df, chunksize=50): 
        '''
        This function collects Headers and stores them into the database. In addition it will use csp evalutor of google to rate the CSP collect from a header or Meta tag
        --> Thread-Safe version 
        '''
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f"[*] PROGRESS - Header Data Collection: {done}/{start_len} - {(done/start_len)*100}%")

            # Create Directory
            os.makedirs(f'{BASE_DIR}/data/collector/headers/', exist_ok=True)

            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

             # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting Header Data Collection for URL: {row.url}")

                # Start the processes
                p = multiprocessing.Process(target=collectHeaders, args=(row.url, row.handle, row.source, self.log, self.get_proxies(), result_queue))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around - 30-60 sec 
            TIMEOUT = 90
            start = time.time()
            
            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")


            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():
                url, handle, source, filepath = result_queue.get()
                self.log.info(f"  [*] Completed Header scan for {url}")

                # For each scan -> read the results (Transfering via queue is too slow)
                try:
                    with open(filepath, "r") as file:
                        data = json.load(file)
                except Exception as e:
                    self.log.info(f"  [!] Error while reading Header data for {url}")

                collected_results.append((url, handle, source, data))
            else:
                self.log.info(f"  [*] Results Empty!")

            # Remove old stuff
            self.log.info(f"[*] Killing still existing remains...")
            # Clear Directory
            deleteDirContent(f'{BASE_DIR}/data/collector/headers/')

            # Write to database in serial (after collection is done)
            for url, handle, source, data in collected_results:
                try:
                    url_entry = self.session_urls.query(Collectors.model.CollectedData_model.Urls).filter_by(
                        identifier=f"{url}-{handle}-{source}"
                    ).first()

                    if url_entry:
                        url_entry.headers = json.dumps(data['headers'])
                        url_entry.csp_rating = json.dumps(data['evaluation'])

                        self.session_urls.commit()
                        self.log.info(f"[*] Data stored for {url}-{handle}-{source}")
                    
                    else: 
                        self.log.error(f"[!] No entry found for {url}-{handle}-{source}")

                except Exception as e:
                    self.log.error(f'[!] Exception caught during storing of header data - {url}-{handle}-{source}: {e}')
                    self.session_urls.rollback()

    def collectCookiesAndIncludesMultiProcess(self, df, chunksize=40):
        '''
        This function collects script includes to count and investigate them later. In addition it will collect cookies set by the webpage and store both data into the database.
        ---> Thread-safe already
        '''

        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f" [*] PROGRESS - CookiesAndIncludes Data Collection: {done}/{start_len} - {(done/start_len)*100}%")

            # Create Directory
            os.makedirs(f'{BASE_DIR}/data/collector/cookie_includes/', exist_ok=True)

            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

             # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting CookiesAndIncludes Data Collection for URL: {row.url}")

                # Start the processes
                p = multiprocessing.Process(target=collectCookieAndIncludes, args=(row.url, row.handle, row.source, self.log, result_queue))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around - 30-60 sec 
            TIMEOUT = 120
            start = time.time()
            
            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")


            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():
                url, handle, source, final_url, filepath = result_queue.get()
                self.log.info(f"  [*] Completed CookiesAndIncludes scan for {url}")

                # For each scan -> read the results (Transfering via queue is too slow)
                try:
                    with open(filepath, "r") as file:
                        data = json.load(file)
                except Exception as e:
                    self.log.info(f"  [!] Error while reading retirejs data for {url}")

                collected_results.append((url, handle, source, final_url, data))
            else:
                self.log.info(f"  [*] Results Empty!")

            # Remove old stuff
            self.log.info(f"[*] Killing still existing remains...")
            try:
                delete_tmp_profiles()
                subprocess.run("pkill firefox", shell=True, check=True)
            except Exception as e:
                if e.returncode == 1:
                    self.log.info("[*] No Firefox processes were running.")

                else:
                    self.log.error(f"[!] Killing still existing remains failed. STOPPTING THEREFORE! (Fills server otherwhise)")
                    exit()

            # Clear Directory
            deleteDirContent(f'{BASE_DIR}/data/collector/cookie_includes/')

            # Write to database in serial (after collection is done)
            for url, handle, source, final_url, data in collected_results:
                try:
                    url_entry = self.session_urls.query(Collectors.model.CollectedData_model.Urls).filter_by(
                        identifier=f"{url}-{handle}-{source}"
                    ).first()

                    if url_entry:
                        url_entry.included_scripts = json.dumps(data['included_scripts'])
                        url_entry.cookies = json.dumps(data['cookies'])
                        url_entry.final_url = final_url

                        self.session_urls.commit()
                        self.log.info(f"[*] Data stored for {url}-{handle}-{source}")
                    
                    else: 
                        self.log.error(f"[!] No entry found for {url}-{handle}-{source}")

                except Exception as e:
                    self.log.error(f'[!] Exception caught during storing of Cookies and Inlcudes data - {url}-{handle}-{source}: {e}')
                    self.session_urls.rollback()
    
    def generateExploitMultiProcess(self, chunksize=20):
        self.log.info("[*] Starting the Generation of Exploits...")
        # Database setup
        output_path = f'{BASE_DIR}/data/collector/findings/'
        dump_path = f'{BASE_DIR}/data/collector/results_exploits.json'

        # ------ PREFILTER HERE ---------
        # This speeds-up since filtering happens earlier - otherwhise only in script of exploit generation
        engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")


        batch_size = 10000
        offset = 0
        total_valid = 0
        processed_rows = 0

        # List to store results
        prefiltered_findings = []

        # Process each chunk
        while True:
            paginated_query = f'SELECT id, url, finding FROM "taints" ORDER BY id LIMIT {batch_size} OFFSET {offset}'
            chunk = pd.read_sql_query(paginated_query, engine)

            if chunk.empty:
                break  # Stop when no more results

            print(f"Processing chunk with {len(chunk)} rows...")

            # Use multiprocessing to process rows in parallel
            with concurrent.futures.ProcessPoolExecutor() as executor:
                results = list(executor.map(process_row, [row for _, row in chunk.iterrows()]))


            # Filter usable results
            valid_results = [res for res in results if res is not None]
            prefiltered_findings.extend(valid_results)

            # Update counters and print intermediate progress
            total_valid += len(valid_results)
            processed_rows += len(chunk)

            print(f"[*] Progress: Processed {processed_rows} rows, Valid findings: {total_valid}")

            offset += batch_size  # Move to next batch

        print(f"[*] Prefiltering complete: {len(prefiltered_findings)} findings kept.")
        with open(f'{BASE_DIR}/data/collector/prefiltered.json', "w") as file:
            json.dump(prefiltered_findings, file)

        # ------- RESULT PROCESSING ------
        results = []
        chunk_size = 30
        prefiltered_findings = [prefiltered_findings[i:i + chunk_size] for i in range(0, len(prefiltered_findings), chunk_size)]
        for chunk in prefiltered_findings:
            self.log.info(f" [*] Starting with a chunk of length {len(chunk)}")
            os.makedirs(output_path, exist_ok=True)

            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunk_size)

            # Create processes
            procs = []
            for url, finding in chunk:
                #self.log.info(f"[*] Starting exploit generation for URL: {url}")

                # Start the processes
                p = multiprocessing.Process(target=generateExploit, args=(finding, url, self.log, result_queue))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around 30-60 sec
            TIMEOUT = 600
            start = time.time()

            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("[*] All subprocesses completed successfully before the timeout.")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"[*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("[!] At least one process timed out, terminating all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f"[*] Process {p.name} timed out and was terminated.")

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"[*] Process {p.name} has finished and cleaned up.")

            # Collect results from the result queue
            while True:
                try:
                    result = result_queue.get(timeout=5)   # wait up to 1 second for an item
                except Exception as e:
                    break                                 # queue is empty → exit loop

                try:
                    filepath = result[1]
                    if filepath is None:
                        continue
                    with open(filepath, "r") as f:
                        results.append(json.load(f))
                except Exception as e:
                    self.log.info(f"  [!] Error while reading exploit data - {e}")


            if os.path.exists(dump_path):
                with open(dump_path, "r") as dump_file:
                    existing_data = json.load(dump_file)
            else:
                existing_data = []
            
            existing_data.extend(results)
            
            with open(dump_path, "w") as dump_file:
                json.dump(existing_data, dump_file, indent=4)
            
            self.log.info(f"[*] Stored {len(results)} generated exploits to results_exploits.json!")
            results.clear()
            self.log.info(f"[*] Finished current chunk - Currently {len(results)} results")
            # Clean up the directory used for I/O of findings and exploits
            self.log.info("[*] Cleaning the directory used for I/O of findings and exploits...")
            deleteDirContent(output_path)


        self.log.info(f"[*] Finished - Found {len(existing_data)} generated exploits !")
        with open(dump_path, "w") as dump_file:
            json.dump(existing_data, dump_file, indent=4)


        # exisitng_data will now hold all exploits generated -> URLs + Storage/Cookies etc.
        return existing_data

    def validateExploitsMultiProcess(self, exploits, chunksize=20):
        output_path = f'{BASE_DIR}/data/collector/findings/'
        self.log.info("[*] Starting the Validation of Exploits...")

        smaller_chunks = [exploits[i:i + chunksize] for i in range(0, len(exploits), chunksize)]
        start_len = len(exploits)
        done = 0

        collected_results = []  # <-- Ergebnisse aller Chunks

        for chunk in smaller_chunks:
            os.makedirs(output_path, exist_ok=True)
            self.log.info(f" [*] PROGRESS - Exploit Validation: {done}/{start_len} - {(done/start_len)*100}%")

            os.makedirs(f'{BASE_DIR}/data/collector/findings/', exist_ok=True)
            done += len(chunk)
            chunk = random.sample(chunk, len(chunk))

            result_queue = multiprocessing.Queue(maxsize=chunksize)
            procs = []

            for i, json_expl in enumerate(chunk):
                self.log.info(f"  [*] Starting Exploit Validation for URL: {json_expl['url']}")
                p = multiprocessing.Process(target=testExploit, args=(json_expl, json_expl['url'], self.log, result_queue))
                procs.append(p)
                p.start()

            TIMEOUT = 120
            start = time.time()

            while time.time() - start <= TIMEOUT:
                unfinished_procs = [p for p in procs if p.is_alive()]
                if not unfinished_procs:
                    self.log.info("  [*] All subprocesses finished successfully before timeout.")
                    break

                for p in unfinished_procs:
                    p.join(timeout=0.1)
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)

                time.sleep(0.1)

            else:
                self.log.error("  [!] At least one process timed out! Terminating all remaining processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")

            # Ergebnisse aus der Queue lesen
            while not result_queue.empty():
                result = result_queue.get()
                url = result[0]
                try:
                    filepath = result[1]
                    with open(filepath, "r") as file:
                        data = json.load(file)

                    if data is not None:
                        success = False
                        for test_results in data:
                            if test_results['validated']:
                                self.log.info(f"  [*] Exploit was validated for {url}")
                                collected_results.append(test_results)
                                success = True

                        if not success:
                            self.log.info(f"  [!] Exploit was not validated for {url}")
                except Exception as e:
                    self.log.info(f"  [!] Error while reading exploit data - {e}")
            else:
                self.log.info(f"  [*] Results Empty!")

            # Storeing what has been done validates so far
            try:
                with open(f'{BASE_DIR}/data/collector/findings/temp-validated-exploits-1.json', "w") as temp_file:
                    json.dump(collected_results, temp_file, indent=4)
                self.log.info("[*] Current status of results is stored.")
            except Exception as e:
                self.log.error(f"[!] Error during storing current status: {e}")

            self.log.info("[*] Cleaning the directory used for I/O of findings and exploits...")
            deleteDirContent(output_path)

        # Finales Speichern aller validierten Exploits
        try:
            with open(f'{BASE_DIR}/data/collector/findings/validated-exploits-{uuid.uuid4()}.json', "w") as file:
                json.dump(collected_results, file, indent=4)
            self.log.info("[*] Finales Speichern der validierten Exploits abgeschlossen.")
        except Exception as e:
            self.log.error(f"[!] Exception während des finalen Speicherns der Ergebnisse: {e}")

    def collectFlowDataMultiProcess(self, df, chunksize=20): 
        '''
        This function starts up foxhound with a predefined profile that has our addon already installed and activated. This enables us to collect the reported taintflows from foxhound into a separated database. 
        '''
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        buffer_timeout_batches = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f" [*] PROGRESS - TaintFlow Data Collection: {done}/{start_len} - {(done/start_len)*100}%")

            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

             # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting TaintFlow Data Collection for URL: {row.url}")

                # Start the processes
                p = multiprocessing.Process(target=collectFlowData, args=(row.url, self.log))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around - 30-60 sec 
            TIMEOUT = 120
            start = time.time()
            
            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")

             # Remove old stuff
            self.log.info(f"[*] Killing still existing remains...")
            try:
                delete_tmp_profiles()
                subprocess.run("pgrep -f foxhound | xargs -r kill", shell=True, check=True)
            except subprocess.CalledProcessError as e:  
                if e.returncode == 1:
                    self.log.info("[*] No Foxhound processes were running.")
                elif e.returncode == -15:  # Ignore SIGTERM
                    self.log.info("[*] Foxhound processes were successfully terminated.")
                else:
                    self.log.error(f"[!] Killing still existing remains failed with return code {e.returncode}. STOPPING THEREFORE!")
                    exit(1)  
            except Exception as e:  
                self.log.error(f"[!] Unexpected error while killing Foxhound processes: {e}")
                exit(1)

            if buffer_timeout_batches >= 25:
                self.log.info("[*] Pausing to prevent overwhelming of the database...")
                time.sleep(10)
                buffer_timeout_batches = 0
            else:
                buffer_timeout_batches += 1
            
    def collectCertificateMultiProcess(self, df, chunksize=30):
        '''
        This function utilizes sslscan to check the certificates for the used mechanisms and potential vulnerabilities. We then store the data in the database.
        --> Thread-safe already
        '''
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f" [*] PROGRESS - Certificate Data Collection: {done}/{start_len} - {(done/start_len)*100}%")

            # Create Directory
            os.makedirs(f'{BASE_DIR}/data/collector/sslscan/', exist_ok=True)

            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

             # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting SSLscan for URL: {row.url}")

                # Start the processes
                p = multiprocessing.Process(target=collectCertificateData, args=(row.url, row.handle, row.source, self.log, result_queue))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around - 30-60 sec 
            TIMEOUT = 120
            start = time.time()
            
            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")


            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():
                url, handle, source, filepath = result_queue.get()
                self.log.info(f"  [*] Completed Certificate scan for {url}")

                # For each scan -> read the results (Transfering via queue is too slow)
                try:
                    with open(filepath, "r") as file:
                        data = json.load(file)
                except Exception as e:
                    self.log.info(f"  [!] Error while reading Certificate data for {url}")

                collected_results.append((url, handle, source, data))
            else:
                self.log.info(f"  [*] Results Empty!")

            # Kill old stuff
            self.log.info(f"[*] Killing still existing remains...")
            try:
                subprocess.run("pkill firefox", shell=True, check=True)
            except Exception as e:
                if e.returncode == 1:
                    self.log.info("[*] No Firefox processes were running.")

                else:
                    self.log.error(f"[!] Killing still existing remains failed. STOPPTING THEREFORE!")
                    exit()

            # Clear Directory
            deleteDirContent(f'{BASE_DIR}/data/collector/sslscan/')

            # Write to database in serial (after collection is done)
            for url, handle, source, data in collected_results:
                try:
                    url_entry = self.session_urls.query(Collectors.model.CollectedData_model.Urls).filter_by(
                        identifier=f"{url}-{handle}-{source}"
                    ).first()

                    if url_entry:
                        url_entry.sslscan = json.dumps(data)

                        self.session_urls.commit()
                        self.log.info(f"[*] Data stored for {url}-{handle}-{source}")
                    
                    else: 
                        self.log.error(f"[!] No entry found for {url}-{handle}-{source}")

                except Exception as e:
                    self.log.error(f'[!] Exception caught during storing of Certificate data - {url}-{handle}-{source}: {e}')
                    self.session_urls.rollback()

    def collectLibVulnDataMultiProcess(self, df, chunksize=30):
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f" [*] PROGRESS - LibVuln Data Collection: {done}/{start_len} - {(done/start_len)*100}%")

            # Create Directory
            os.makedirs(f'{BASE_DIR}/data/collector/retirejs/', exist_ok=True)

            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

             # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting LibVuln Data Collection for URL: {row.url}")

                # Start the processes
                p = multiprocessing.Process(target=collectLibVulnData, args=(row.url, row.handle, row.source, self.log, result_queue))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around - 5-40 sec 
            TIMEOUT = 60
            start = time.time()
            
            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")


            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():                
                url, handle, source, filepath = result_queue.get()
                self.log.info(f"  [*] Completed retirejs scan for {url}")

                # For each scan -> read the results (Transfering via queue is too slow)
                try:
                    with open(filepath, "r") as file:
                        data = json.load(file)
                    collected_results.append((url, handle, source, data))
                except Exception as e:
                    self.log.info(f"  [!] Error while reading retirejs data for {url}")
            else:
                self.log.info(f"  [*] Results Empty!")

            # Kill old stuff
            self.log.info(f"[*] Killing still existing remains...")
            try:
                delete_tmp_profiles()
                subprocess.run("pkill chrome", shell=True, check=True)
            except Exception as e:
                if e.returncode == 1:
                    self.log.info("[*] No Chrome processes were running.")

                else:
                    self.log.error(f"[!] Killing still existing remains failed. STOPPTING THEREFORE!")
                    exit()

            # Clear Directory
            deleteDirContent(f'{BASE_DIR}/data/collector/retirejs/')
            delete_tmp_profiles()

            # Write to database in serial (after collection is done)
            for url, handle, source, data in collected_results:
                try:
                    url_entry = self.session_urls.query(Collectors.model.CollectedData_model.Urls).filter_by(
                        identifier=f"{url}-{handle}-{source}"
                    ).first()

                    if url_entry:
                        url_entry.retirejs = json.dumps(data)

                        self.session_urls.commit()
                        self.log.info(f"[*] Data stored for {url}-{handle}-{source}")
                    
                    else: 
                        self.log.error(f"[!] No entry found for {url}-{handle}-{source}")

                except Exception as e:
                    self.log.error(f'[!] Exception caught during storing of LibVuln data - {url}-{handle}-{source}: {e}')
                    self.session_urls.rollback()

    def collectLighthouseMultiProcess(self, df, chunksize=20):
        '''
        This function collects the lighthouse score of the single websites and stores them along with additional information into the database. 
        --> Thread-safe 
        '''
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f" [*] PROGRESS - Lighthouse Collection: {done}/{start_len} - {(done/start_len)*100}%")

            # Create Directory
            os.makedirs(f'{BASE_DIR}/data/collector/lighthouse/', exist_ok=True)

            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

             # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting lighhouse Collection for URL: {row.url}")

                # Start the processes
                p = multiprocessing.Process(target=collectLighthouse, args=(row.url, row.handle, row.source, self.log, self.get_proxies(), result_queue))
                procs.append(p)
                p.start()

            # Timeout for waiting for processes -> normally should take around - 30-60 sec 
            TIMEOUT = 120
            start = time.time()
            
            # Wait until all processes finish or timeout is reached
            while time.time() - start <= TIMEOUT:
                # Check for completed processes
                unfinished_procs = [p for p in procs if p.is_alive()]

                if not unfinished_procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break  # All processes finished early

                for p in unfinished_procs:
                    p.join(timeout=0.1)  # Timeout for each process if needed
                    if not p.is_alive():
                        self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")
                        procs.remove(p)  # Remove finished process from list

                time.sleep(0.1)  # Small sleep to prevent CPU overuse

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still active processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Ensure all processes are joined and cleaned up
            for p in procs:
                p.join()
                self.log.debug(f"  [*] Process {p.name} has finished and cleaned up.")


            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():
                url, handle, source, filepath = result_queue.get()
                self.log.info(f"  [*] Completed lighthouse scan for {url}")

                # For each scan -> read the results (Transfering via queue is too slow)
                try:
                    with open(filepath, "r") as file:
                        data = json.load(file)
                except Exception as e:
                    self.log.info(f"  [!] Error while reading lighhouse data for {url}")



                collected_results.append((url, handle, source, data))
            else:
                self.log.info(f"  [*] Results Empty!")

            # Kill still running chrome + crashpad + lighthouse processes etc
            self.log.info(f"[*] Killing still existing remains...")
            try:

                subprocess.run("pkill chrome", shell=True, check=True)
                subprocess.run("rm -rf /tmp/.com.google.Chrome.*", shell=True, check=True)
                subprocess.run("rm -rf /tmp/.org.chromium.Chromium.*", shell=True, check=True)

            except Exception as e:
                if e.returncode == 1:
                    self.log.info("[*] No Chrome processes were running.")

                else:
                    self.log.error(f"[!] Killing still existing remains failed. STOPPTING THEREFORE!")
                    exit()

            # Clear Directory
            deleteDirContent(f'{BASE_DIR}/data/collector/lighthouse/')

            # Write to database in serial (after collection is done)
            for url, handle, source, data in collected_results:
                try:
                    url_entry = self.session_urls.query(Collectors.model.CollectedData_model.Urls).filter_by(
                        identifier=f"{url}-{handle}-{source}"
                    ).first()

                    if url_entry:
                        url_entry.lighthouse = json.dumps(data)

                        self.session_urls.commit()
                        self.log.info(f"[*] Data stored for {url}-{handle}-{source}")
                    
                    else: 
                        self.log.error(f"[!] No entry found for {url}-{handle}-{source}")

                except Exception as e:
                    self.log.error(f'[!] Exception caught during storing of Lighthouse data - {url}-{handle}-{source}: {e}')
                    self.session_urls.rollback()

    def collectSubpagesMultiProcess(self, df, max_pages=10, max_depth=2, chunksize=15):
        # split the df into parts to store inbetween
        smaller_dfs = [df.iloc[i:i + chunksize] for i in range(0, len(df), chunksize)]
        start_len = len(df)
        done = 0
        
        for smaller_df in smaller_dfs:
            self.log.info(f" [*] PROGRESS - Subpage Collection: {done}/{start_len} - {(done/start_len)*100}%")
            done = done + len(smaller_df)
            smaller_df = smaller_df.sample(frac=1, random_state=1).reset_index(drop=True)
            
            # Create the result queue to collect results from subprocesses
            result_queue = multiprocessing.Queue(maxsize=chunksize)

            # Create processes
            procs = []
            for i, row in enumerate(smaller_df.itertuples(index=True, name='Pandas')):
                self.log.info(f"  [*] Starting subprocess for URL: {row.url}")

                # Start the process
                p = multiprocessing.Process(target=collectSubpages, args=(row.url, row.handle, row.source, self.log, result_queue, max_pages, max_depth))
                procs.append(p)
                p.start()


            # Timeout for waiting for processes -> 3 attempts max and 60 seconds each
            TIMEOUT = 600  
            start = time.time()
            
            while time.time() - start <= TIMEOUT:
                if not procs:
                    self.log.info("  [*] Every subprocess was successfully executed before timeout was reached!")
                    break
                for p in procs:
                    if p.is_alive():
                        # Not yet finished
                        continue
                    procs.remove(p)  # Remove from list as it is finished
                    p.join()  # Ensure the process is properly cleaned up
                    print(f"Process {p.name} has finished and cleaned up.")
                
                time.sleep(0.1)

            else:
                # Timeout exceeded, terminate processes
                self.log.error("  [!] At least one process timed out!, killing all still acticve processes.")
                for p in procs:
                    p.terminate()
                    self.log.info(f'  [!] -> The Process: {p.name} timed out and was terminated.')

            # Collect results from the result_queue
            collected_results = []
            while not result_queue.empty():
                url, handle, source, subpages = result_queue.get()
                self.log.info(f"  [*] Completed collecting subpages for {url}")
                collected_results.append((url, handle, source, subpages))
            else:
                self.log.info(f"  [*] Results Empty!")

            self.log.info(f"[*] Killing still existing remains...")
            try:
                delete_tmp_profiles()
                subprocess.run("pkill firefox", shell=True, check=True)
            except Exception as e:
                if e.returncode == 1:
                    self.log.info("[*] No Firefiox processes were running.")
                else:
                    self.log.error(f"[!] Killing still existing remains failed. STOPPTING THEREFORE!")
                    exit()

            # Write to database in serial (after collection is done)
            for url, handle, source, subpages in collected_results:
                for subpage in subpages:
                    try:
                        url_entry = self.session_urls.query(Collectors.model.CollectedData_model.Urls).filter_by(
                            identifier=f"{subpage}-{handle}-{source}"
                        ).first()

                        if not url_entry:
                            new_url_entry = Collectors.model.CollectedData_model.Urls(
                                identifier=f"{subpage}-{handle}-{source}",
                                url=subpage,
                                handle=handle,
                                source=source,
                                base=0,
                                base_url=url,
                            )
                            self.session_urls.add(new_url_entry)
                            self.session_urls.commit()

                            cleaned_url = subpage.replace("https://www.", "").replace("http://www.", "").replace("https://", "").replace("http://","")

                            # add to df
                            new_entry = {
                                'identifier': f'{subpage}-{row.handle}-{row.source}',
                                'url': subpage,
                                'handle': row.handle,
                                'source': row.source,
                                'base_url': row.url,
                                'base': 0,
                                'cleaned_url': cleaned_url
                            }
                            df.loc[len(df)] = new_entry

                        else:
                            self.log.info(f' [!] This Subpage was already added!')

                    except Exception as e:
                        self.log.error(f'[*] Exception caught during storing subpage {subpage}: {e}')
                        self.session_urls.rollback()

                self.log.info(f' [*] Discovered Subpages for {row.url} added!')
        return df

    def main(self, intensity=100):
        # Those default values == 100 were the one we used
        scale = intensity / 100
        CHUNKSIZE_HEADERS = max(1, int(50 * scale))
        CHUNKSIZE_COOKIES_INC = max(1, int(40 * scale))
        CHUNKSIZE_RETIREJS = max(1, int(30 * scale))
        CHUNKSIZE_SUBPAGES = max(1, int(15 * scale))
        CHUNKSIZE_FLOWS = max(1, int(20 * scale))
        CHUNKSIZE_EXPLOITS = max(1, int(20 * scale))
        NUM_PROXIES = max(1, int(40 * scale))



        # ---------- FILTERING -------------
        collectedData = self.readDataFromDB()
        # To stop scanning webvsites just because of www or https once give and once not
        collectedData['cleaned_url'] = collectedData['url'].replace(
            {
                "https://www.": "",
                "http://www.": "",
                "https://": "",
                "http://": "",
            }, 
            regex=True
        )

        # Drop duplicates
        BBUrls = collectedData[collectedData['source'] == 'BB'].copy()
        BBUrls = BBUrls.drop_duplicates(subset='cleaned_url', keep='first')
        # Drop for now those that have wild cards and those having app schema
        BBUrls = BBUrls[~BBUrls['url'].str.startswith(('http://com.', 'https://com.'), na=False)]
        BBUrls = BBUrls[~BBUrls['url'].str.contains(r'\*', na=False)]

        # Drop duplicates
        CruxUrls = collectedData[collectedData['source'] == 'CRUX'].copy()
        CruxUrls = CruxUrls.drop_duplicates(subset='cleaned_url', keep='first')
        # Drop for now those that have wild cards and those having app schema
        CruxUrls = CruxUrls[~CruxUrls['url'].str.startswith(('http://com.', 'https://com.'), na=False)]
        CruxUrls = CruxUrls[~CruxUrls['url'].str.contains(r'\*', na=False)]

        # ---------- SAMPLEING -------------
        self.log.info(f"[*] Currently BB Dataset is of size {len(BBUrls)}")
        BBUrls = BBUrls.sample(n=0, random_state=1)
        self.log.info(f"[*] Sampled BB Dataset is of size {len(BBUrls)}")

        self.log.info(f"[*] Currently CrUX Dataset is of size {len(CruxUrls)}")
        CruxUrls = CruxUrls.sample(n=50, random_state=1)
        self.log.info(f"[*] Sampled CrUX Dataset is of size {len(CruxUrls)}")


        # ------ Subpage discovery --------
        self.teleBot.info("[*] Now starting the Collecting of up to 10 subpages per collected website!")
        self.log.info("[*] Now starting the Collecting of up to 10 subpages per collected website!")
        self.collectSubpagesMultiProcess(BBUrls, 10, 2, CHUNKSIZE_SUBPAGES)
        self.collectSubpagesMultiProcess(CruxUrls, 10, 2, CHUNKSIZE_SUBPAGES)
       
        collectedData = self.readDataFromDB() 
        # To stop scanning webvsites just because of www or https once give and once not
        collectedData['cleaned_url'] = collectedData['url'].replace(
            {
                "https://www.": "",
                "http://www.": "",
                "https://": "",
                "http://": "",
            }, 
            regex=True
        )

        # Drop duplicates
        BBUrls = collectedData[collectedData['source'] == 'BB'].copy()
        BBUrls = BBUrls.drop_duplicates(subset='cleaned_url', keep='first')
        # Drop for now those that have wild cards and those having app schema
        BBUrls = BBUrls[~BBUrls['url'].str.startswith(('http://com.', 'https://com.'), na=False)]
        BBUrls = BBUrls[~BBUrls['url'].str.contains(r'\*', na=False)]

        # Drop duplicates
        CruxUrls = collectedData[collectedData['source'] == 'CRUX'].copy()
        CruxUrls = CruxUrls.drop_duplicates(subset='cleaned_url', keep='first')
        # Drop for now those that have wild cards and those having app schema
        CruxUrls = CruxUrls[~CruxUrls['url'].str.startswith(('http://com.', 'https://com.'), na=False)]
        CruxUrls = CruxUrls[~CruxUrls['url'].str.contains(r'\*', na=False)]

        self.log.info(f'BBURLS: {len(BBUrls)}')
        self.teleBot.info(f'[*] Including Subpages - Collection starts for {len(BBUrls)} BB URLs')
        self.log.info(f'CRUXURLS: {len(CruxUrls)}')
        self.teleBot.info(f'[*] Including Subpages - Collection starts for {len(CruxUrls)} CRUX URLs')


        #  -------------- STARTUP STUFF -------------------
        # Start the taint receiving Server + Create it's database
        working_dir = f'{BASE_DIR}/data/collector/additionalData/foxhound_taints/extension'
        log_file_taint = f'{BASE_DIR}/logs/TaintServerLog.log'

        print("[*] Initializing taint database...")
        subprocess.run(
                [
                    "python3", 
                    "createDB.py"
                ], 
                cwd=working_dir, 
                check=True
            )
        print("[+] Database ready")


        time.sleep(10)
        num_workers = "1"
        taint_command = [
            "gunicorn",
            "python_backend:app",
            "-k",
            "uvicorn.workers.UvicornWorker",
            "--workers",
            num_workers,
            "--bind",
            "0.0.0.0:8000",
            "--graceful-timeout", "180",
            "--keep-alive", "120"
        ]

        try:
            log_file_taint = open(log_file_taint, 'w+')
            time.sleep(1)
            taint_process = subprocess.Popen(
                taint_command, 
                cwd=working_dir, 
                stdout=log_file_taint, 
                stderr=log_file_taint,
                )
            self.log.info("[+] Taint receiving server started successfully in the background.")
        except Exception as e:
            self.log.error(f"[!] Exception occurred while starting the taint receiving server!: {e}")
        
        # Start the MitM Proxy Tool + Setup needed env variable
        proxy_base_port = 9090
        number_proxy = NUM_PROXIES
        proxy_list = []
        for x in range(0, number_proxy):
            proxy_list.append(
                {
                    'http': f'http://127.0.0.1:{proxy_base_port + x}',
                    'https': f'http://127.0.0.1:{proxy_base_port + x}'
                }
            )
        self.proxies = proxy_list
        proxy_processes = start_proxy_instances(number_proxy, proxy_base_port, f'{BASE_DIR}/src/Helper/Proxy', f'{BASE_DIR}/logs' )

        # -> For tools using requests we set the Cert to be trusted
        os.environ['REQUESTS_CA_BUNDLE'] = f'{BASE_DIR}/src/Helper/Proxy/certs/mitmproxy-ca-cert.pem'        
        # wait until background tasks are ready
        time.sleep(10)

        # Shuffle the dataset to reduce the probability of running a test against one server at once
        BBUrls = BBUrls.sample(frac=1, random_state=1).reset_index(drop=True)
        CruxUrls = CruxUrls.sample(frac=1, random_state=1).reset_index(drop=True)
        
        # ------------ START METRICS COLLECTION ------------
        self.teleBot.info("[*] Starting Header/CSP Collection...")
        self.log.info("[*] Starting Header/CSP Collection")
        self.collectHeadersMultiProcess(BBUrls, CHUNKSIZE_HEADERS) 
        self.collectHeadersMultiProcess(CruxUrls, CHUNKSIZE_HEADERS)
        self.teleBot.info("[*] Finished Header/CSP Collection")

        self.teleBot.info("[*] Starting Cookies/Includes Collection...")
        self.log.info("[*] Starting Cookies/Includes Collection")
        self.collectCookiesAndIncludesMultiProcess(BBUrls, CHUNKSIZE_COOKIES_INC)
        self.collectCookiesAndIncludesMultiProcess(CruxUrls, CHUNKSIZE_COOKIES_INC)
        self.teleBot.info("[*] Finished Cookies/Includes Collection")

        # ONLY SCAN TOPLEVEL DOMAINS -> Only Base URLs -> no subpages
        self.teleBot.info("[*] Starting Certificate Collection...")
        self.log.info("[*] Starting Certificate Collection")
        CruxUrlsCert = CruxUrls.copy()
        BBUrlsCert = BBUrls.copy()
        CruxUrlsCert = CruxUrlsCert[CruxUrlsCert['base'] == 1]
        BBUrlsCert = BBUrlsCert[BBUrlsCert['base'] == 1]
        self.collectCertificateMultiProcess(BBUrlsCert)
        self.collectCertificateMultiProcess(CruxUrlsCert)
        self.teleBot.info("[*] Finished Certificate Collection")


        self.teleBot.info("[*] Starting Lib Collection...")
        self.log.info("[*] Starting Lib Collection")
        self.collectLibVulnDataMultiProcess(BBUrls, CHUNKSIZE_RETIREJS)
        self.collectLibVulnDataMultiProcess(CruxUrls, CHUNKSIZE_RETIREJS)
        self.teleBot.info("[*] Finished Lib Collection")


        # Skipped for paper - used as part of the thesis
        
        self.teleBot.info("[*] Starting Lighthouse Scan/Collection...")
        self.log.info("[*] Starting Lighthouse Scan/Collection")
        self.collectLighthouseMultiProcess(BBUrls)
        self.collectLighthouseMultiProcess(CruxUrls)
        self.teleBot.info("[*] Finished Lighthouse Scan/Collection")
    

        self.teleBot.info("[*] Starting XSS Scan/Collection...")
        self.log.info("[*] Starting XSS Scan/Collection")
        self.collectFlowDataMultiProcess(BBUrls, CHUNKSIZE_FLOWS)
        self.collectFlowDataMultiProcess(CruxUrls, CHUNKSIZE_FLOWS)
        self.log.info("[*] Finished XSS Scan/Collection")
        self.teleBot.info("[*] Finished XSS Scan/Collection")
        
    
        # Verfication how well the exploit generation works and which cases are automatically exploitable 
        include_tests = False
        if include_tests:
            url_list = [
                "https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/document/cookie/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/document/referrer/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/document/referrer/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/document/referrer/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/window/name/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/window/name/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/window/name/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/localStorage/array/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/localStorage/function/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/localStorage/function/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/localStorage/function/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/localStorage/property/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/localStorage/array/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/localStorage/function/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/localStorage/function/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/localStorage/function/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/localStorage/property/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/sessionStorage/array/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/sessionStorage/function/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/sessionStorage/function/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/sessionStorage/function/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/sessionStorage/property/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/sessionStorage/array/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/sessionStorage/function/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/sessionStorage/function/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/sessionStorage/function/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/external/sessionStorage/property/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval",
                "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml",
                "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite",
                "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval",
                "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison",
                "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp",
                "https://public-firing-range.appspot.com/dom/eventtriggering/document/formSubmission/eval",
                "https://public-firing-range.appspot.com/dom/eventtriggering/document/formSubmission/innerHtml",
                "https://public-firing-range.appspot.com/dom/eventtriggering/document/formSubmission/documentWrite",
                "https://public-firing-range.appspot.com/dom/eventtriggering/document/inputTyping/eval",
                "https://public-firing-range.appspot.com/dom/eventtriggering/document/inputTyping/innerHtml",
                "https://public-firing-range.appspot.com/dom/eventtriggering/document/inputTyping/documentWrite",
                "https://public-firing-range.appspot.com/dom/javascripturi.html",
                "https://public-firing-range.appspot.com/dom/dompropagation/"
            ]
            for url in url_list:
                collectFlowData(url, self.log)


        self.teleBot.info("[*] Starting XSS Exploit Generation and Validation...")
        self.log.info("[*] Starting XSS Exploit Generation and Validation...")
        exploits = self.generateExploitMultiProcess(CHUNKSIZE_EXPLOITS)
        self.validateExploitsMultiProcess(exploits, CHUNKSIZE_EXPLOITS)
        self.teleBot.info("[*] Finished XSS Exploit Generation and Validation...")
        self.log.info("[*] Finished XSS Exploit Generation and Validation...")

        # Close log files and proxies
        for proxy_process, log_file in proxy_processes:
            proxy_process.terminate()
            proxy_process.wait()
            log_file.close()
        
        
