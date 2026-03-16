#!/bin/bash
set -e

cd "$(dirname "$0")"
BASE_DIR="$PWD"


# -------------- .ENV for secrets --------------

# check .env
if [ ! -f "$BASE_DIR/.env" ]; then
    cp "$BASE_DIR/config.example.env" "$BASE_DIR/.env"
    echo "[!] WICHTIG: .env wurde erstellt - bitte konfigurieren bevor du weitermachst!"
    echo "    nano $BASE_DIR/.env"
    exit 1
fi

# load .env variables
while IFS= read -r line; do
    # skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] && continue
    [[ -z "$line" ]] && continue
    # remove spaces around =
    line=$(echo "$line" | sed 's/ *= */=/g')
    export "$line" 2>/dev/null || true
done < "$BASE_DIR/.env"
# -------------- External (GIT) Dependencies --------------

echo "[*] Setting up external dependencies"

# RetireJS modified (pinned to 2.2.4)
if [ ! -d "$BASE_DIR/src/external/retirejs" ]; then
    git clone --depth 1 --branch 2.2.4 https://github.com/RetireJS/retire.js.git "$BASE_DIR/src/external/retirejs"
    # Apply our custom changes (playwright extraction via content.js)
    git -C "$BASE_DIR/src/external/retirejs" apply "$BASE_DIR/src/external/changes/retirejs_diff.patch"
fi

# ISDCAC Chrome Extension (pinned to v1.1.4)
if [ ! -d "$BASE_DIR/src/external/ISDCAC" ]; then
    git clone --depth 1 --branch v1.1.4 https://github.com/OhMyGuus/I-Still-Dont-Care-About-Cookies.git "$BASE_DIR/src/external/ISDCAC"
fi

# persistent-clientside-xss
if [ ! -d "$BASE_DIR/src/external/persistent-clientside-xss-for-login-security" ]; then
    git clone https://github.com/thelbrecht/persistent-clientside-xss-for-login-security.git "$BASE_DIR/src/external/persistent-clientside-xss-for-login-security"
    # Apply our custom changes (file handling)
    git -C "$BASE_DIR/src/external/persistent-clientside-xss-for-login-security" apply "$BASE_DIR/src/external/changes/xss-exploit_diff.patch"
fi

echo "[+] External dependencies ready"

# -------------- PIP/VENV Dependencies --------------

echo "[*] Installing dependencies"
# dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libncurses5-dev \
    libreadline-dev \
    libffi-dev \
    wget \
    libpq-dev \
    unzip



echo "[*] Building local Python 2.7 runtime"
# download python2
if [ ! -d "Python-2.7.18" ]; then
    wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz
    tar -xf Python-2.7.18.tgz
fi

cd Python-2.7.18

./configure --prefix="$BASE_DIR/py2local" \
    --enable-shared \
    LDFLAGS="-Wl,-rpath,$BASE_DIR/py2local/lib"
make -j$(nproc)
make install

cd "$BASE_DIR"

# create virtualenv
./py2local/bin/python2.7 -m ensurepip
./py2local/bin/pip install virtualenv
./py2local/bin/virtualenv masterenv_python2

# install requirements into venv
./masterenv_python2/bin/pip install -r $BASE_DIR/src/external/persistent-clientside-xss-for-login-security/src/requirements.txt

echo "[+] Python2 environment ready"


# -------------- PIP/VENV Dependencies --------------

echo "[*] Setting up Python3 virtual environment"

sudo apt-get install -y python3 python3-pip python3-venv

python3 -m venv "$BASE_DIR/.venv"
"$BASE_DIR/.venv/bin/pip" install --upgrade pip
"$BASE_DIR/.venv/bin/pip" install -r "$BASE_DIR/requirements.txt"

echo "[+] Python3 environment ready"

# -------------- mitmproxy symlinks --------------
sudo ln -sf "$BASE_DIR/.venv/bin/mitmdump" /usr/local/bin/mitmdump
sudo ln -sf "$BASE_DIR/.venv/bin/mitmproxy" /usr/local/bin/mitmproxy

# -------------- gunicorn symlinks --------------
sudo ln -sf "$BASE_DIR/.venv/bin/gunicorn" /usr/local/bin/gunicorn


# -------------- mitmproxy CA cert --------------
echo "[*] Generating mitmproxy CA cert"
mkdir -p "$BASE_DIR/src/Helper/Proxy/certs"
mitmdump --set confdir="$BASE_DIR/src/Helper/Proxy/certs" &
MITM_PID=$!
sleep 3
kill $MITM_PID 2>/dev/null || true
echo "[+] mitmproxy CA cert ready"


# -------------- Foxhound --------------

echo "[*] Installing Foxhound"

FOXHOUND_URL="https://foxhound.ias.tu-bs.de/archives/foxhound_linux_v1.58.2_09dda176a6bdf6b52e1eda728f8a4a6663e88931.zip"
FOXHOUND_DIR="$BASE_DIR/src/external/foxhound"

if [ ! -d "$FOXHOUND_DIR" ]; then
    wget -O /tmp/foxhound.zip "$FOXHOUND_URL"
    unzip /tmp/foxhound.zip -d "$FOXHOUND_DIR"
    rm /tmp/foxhound.zip
    chmod +x "$FOXHOUND_DIR/foxhound"
fi

echo "[+] Foxhound ready"


# -------------- Playwright Browsers --------------

echo "[*] Installing Playwright browsers"

# Ubuntu 24 fix for libasound2 rename
sudo apt-get install -y libasound2t64 2>/dev/null || true
# symlink so playwright finds it
sudo ln -sf /usr/lib/x86_64-linux-gnu/libasound.so.2 /usr/lib/x86_64-linux-gnu/libasound.so 2>/dev/null || true

"$BASE_DIR/.venv/bin/playwright" install firefox chromium
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0 "$BASE_DIR/.venv/bin/playwright" install-deps firefox chromium 2>/dev/null || true

echo "[+] Playwright browsers ready"

# -------------- PostgreSQL --------------

echo "[*] Setting up PostgreSQL"
sudo apt-get install -y postgresql postgresql-contrib

sudo systemctl start postgresql
sudo systemctl enable postgresql

# DB und User anlegen
sudo -u postgres psql -c "CREATE USER $DB_USER_PG WITH PASSWORD '$DB_PASS_PG';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME_PG OWNER $DB_USER_PG;" 2>/dev/null || true

echo "[+] PostgreSQL ready"