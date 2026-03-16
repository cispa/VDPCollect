## VDPCollect

VDPCollect is a research pipeline for collecting, normalizing and enriching data about Vulnerability Disclosure Programs (VDPs) and bug bounty programs.  
It aggregates scopes from public lists and major platforms, extracts target URLs, and then crawls them to collect security‑relevant data such as headers, cookies, CSPs and taint flows.

### Main components

- **Public list scrapers** (`src/PublicListScrappers/`):  
  Import programs and scopes from:
  - ProjectDiscovery Chaos list
  - FireBounty
  - Arkadiyt’s bounty‑targets data

- **Platform scrapers** (`src/BBScrapper/`):  
  Collect structured data from providers like HackerOne, Bugcrowd, Intigriti and YesWeHack and store them in local SQLite databases.

- **URL extractor** (`src/Extractor/ExtractURLs.py`):  
  Merges provider data, extracts valid URLs / hostnames, increses the scope by searching for subdomains in cases where a wildcard domain is considered as in-scope, optionally uses OpenAI to infer rate limits and required custom headers from program policies, and writes results into `data/CollectedData.sqlite`.
  
  In here the extraction of the allowed Vulnerability Types should be added - In our case it was only used as Post-Analysis since we restricted ourselves to XSS-

- **Collector** (`src/Collectors/Collector.py`):  
  Uses Playwright, mitmproxy and a tainted Firefox (`foxhound`) to visit URLs and collect:
  - Collects subpages to enricht the dataset
  - HTTP headers and cookies
  - CSPs (analyzed via Google’s `csp_evaluator` Node module)
  - Included JavaScript and other metadata
  - Optional DOM taint flows written to a Postgres database
  - Generates and tests XSS Exploits based on the extracted flows

- **Monitoring / telemetry** (`src/Helper/Monitoring/`):  
  Simple Telegram bot integration for status and error notifications, plus an optional resource monitor.

### Repository layout (simplified)

- `src/main.py` – Entry point orchestrating the pipeline (collection phases I & II).
- `src/BBScrapper/` – Scrapers for HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.
- `src/PublicListScrappers/` – Scrapers for public scope lists (ProjectDiscovery, FireBounty, bounty‑targets).
- `src/Extractor/ExtractURLs.py` – URL extraction and enrichment.
- `src/Collectors/` – Header/CSP/cookie/taint collection logic and models.
- `src/config/db_factory.py` – Helper to create SQLAlchemy engines and sessions for the local SQLite databases in `data/`.
- `data/` – Databases, intermediate results and collector outputs.
- `data/collector/additionalData/foxhound_taints/extension/` – Foxhound taint backend and DB setup.
- `install.sh` – Helper script to build a local Python 2.7 environment for the exploit generator.
- `requirements.txt` – Python 3 dependencies for the main pipeline.

---

## Prerequisites
We are working on providing a complete out-of-the-box running version of our tool. The installation will need some further changes especially inside the install.sh and related code.

Note: This project was developed as part of a master's thesis and grew organically for local use. It is still a work in progress and not yet production-ready. Some components may require manual configuration or adjustment depending on your environment.

## Configuration

### Environment file (`.env`)

The project uses a root `.env` file for configuration. A template is provided as `config.example.env` — `install.sh` will copy it to `.env` automatically on first run.

#### Database (PostgreSQL)
- `DB_USER_PG` – Postgres username
- `DB_PASS_PG` – Postgres password
- `DB_HOST_PG` – Postgres host (default `127.0.0.1`)
- `DB_PORT_PG` – Postgres port (default `5432`)
- `DB_NAME_PG` – Database name

#### AI / LLM
- `CHATGPT_API_KEY` – OpenAI API key

#### Monitoring
- `TELEGRAM_API_CODE` – Telegram bot token
- `TELEGRAM_CHAT_ID` – Telegram chat ID

#### Foxhound
- `FOXHOUND_BINARY` – Path to Foxhound binary (default `src/external/foxhound/foxhound`)

#### Bug Bounty Platform Credentials
- `YESWEHACK_EMAIL`, `YESWEHACK_PASSWORD`, `YESWEHACK_TOKEN`, `YESWEHACK_INTERCOM_SESSION`
- `BUGCROWD_EMAIL`, `BUGCROWD_SESSION`, `BUGCROWD_CROWDCONTROL`, `BUGCROWD_CSRF_TOKEN`
- `HACKERONE_EMAIL`, `HACKERONE_PASSWORD`, `H1_SESSION`, `H1_CF_CLEARANCE`, `H1_DEVICE_ID`, `H1_STRIPE_MID`, `H1_STRIPE_SID`
- `INTIGRITI_EMAIL`, `INTIGRITI_PASSWORD`, `INTIGRITI_SESSION`, `INTIGRITI_CSRF`, `INTIGRITI_INTERCOM_SESSION`

## Running the pipeline

Once setup is complete, the pipeline can be started via:
```bash
python3 src/main.py
```

> **Note:** This project was developed as part of a master's thesis and grew organically for local use. It is still a work in progress and not yet production-ready. Some components may require manual configuration or adjustment depending on your environment.

Be aware that:

- Provider scrapers depend on valid credentials and may break if providers change their HTML/flows.
- This can be network‑ and time‑intensive, and may stress external services if mis‑configured.  
  Use responsibly and respect each provider's terms and rate limits.
---

## Development notes

- **Python version:** The main pipeline is Python 3; only the exploit generator uses Python 2 (via `install.sh`).
- **Databases:** All persistent program/scope/url data is stored in SQLite under `data/`.  
  The taint backend uses PostgreSQL if configured.

---

## License and usage

This repository builds on and bundles third‑party code:

Please review the original licenses in the bundled subprojects and ensure your use of this code complies with those terms and with the terms of any external services you access (bug bounty platforms, public lists, etc.).

