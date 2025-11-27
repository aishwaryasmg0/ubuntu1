#!/bin/bash
set -e

echo "[*] Fixing broken CD-ROM repository (if exists)..."
sudo sed -i '/cdrom/d' /etc/apt/sources.list || true

echo "[*] Updating system..."
sudo apt update && sudo apt upgrade -y

echo "[*] Installing base dependencies..."
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip build-essential golang-go jq nmap

#########################################################
#                FIX GOPATH FOR vboxuser                #
#########################################################

echo "[*] Configuring Go environment for user..."

export GOPATH="/home/vboxuser/go"
export PATH="$PATH:/usr/local/go/bin:/home/vboxuser/go/bin"

mkdir -p "/home/vboxuser/go"
mkdir -p "/home/vboxuser/go/bin"
mkdir -p "/home/vboxuser/go/pkg"

# Persist Go path
echo 'export GOPATH=/home/vboxuser/go' >> ~/.bashrc
echo 'export PATH=$PATH:/usr/local/go/bin:/home/vboxuser/go/bin' >> ~/.bashrc

#########################################################

echo "[*] Creating Python virtualenv and installing Sublist3r inside it..."
# Use a local project virtual environment so python tooling doesn't require sudo
VENV_DIR="$(pwd)/venv"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
# Activate and install sublist3r (idempotent)
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel
python -m pip install --no-warn-script-location sublist3r || true
deactivate

echo "[*] Sublist3r installed in virtualenv at: $VENV_DIR"

#########################################################
#                INSTALL GO-BASED TOOLS                 #
#########################################################

echo "[*] Installing Amass..."
go install -v github.com/owasp-amass/amass/v4/...@latest || go install -v github.com/owasp-amass/amass/v3/...@latest

echo "[*] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[*] Installing GoSpider..."
go install -v github.com/jaeles-project/gospider@latest

echo "[*] Installing gau..."
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo "[*] Installing waybackurls..."
go install -v github.com/tomnomnom/waybackurls@latest

echo "[*] Installing ffuf..."
go install -v github.com/ffuf/ffuf@latest

#########################################################
#                AUTO-INSTALL NUCLEI                    #
#########################################################

echo "[*] Detecting latest Nuclei release..."

LATEST_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
| grep browser_download_url \
| grep linux_amd64 \
| head -n 1 \
| cut -d '"' -f 4)

if [ -z "$LATEST_URL" ]; then
    echo "[-] ERROR: Could not fetch latest Nuclei release download URL!"
    exit 1
fi

echo "[+] Nuclei package found:"
echo "$LATEST_URL"

echo "[*] Downloading Nuclei..."
FILENAME=$(basename "$LATEST_URL")
wget "$LATEST_URL" -O "$FILENAME"

echo "[*] Extracting Nuclei..."

if [[ "$FILENAME" == *.zip ]]; then
    unzip "$FILENAME" -d nuclei_extract
    sudo mv nuclei_extract/nuclei /usr/local/bin/nuclei
    rm -rf nuclei_extract
else
    tar -xvf "$FILENAME"
    sudo mv nuclei /usr/local/bin/nuclei 2>/dev/null || true
fi

sudo chmod +x /usr/local/bin/nuclei
rm -f "$FILENAME"
echo "[+] Nuclei installed successfully!"

#########################################################

echo "[*] Installing sqlmap..."
sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap || true
sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

echo "[*] Installing dirsearch..."
sudo git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch || true
sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

echo "[*] Installing SecLists..."
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists || true

#########################################################
#               VERIFY TOOL INSTALLATIONS               #
#########################################################

echo "[*] Verifying installations..."

TOOLS=("sublist3r" "amass" "httpx" "gospider" "gau" "waybackurls" "ffuf" "nuclei" "sqlmap" "dirsearch")

for tool in "${TOOLS[@]}"; do
    if command -v $tool &>/dev/null; then
        echo "[✔] $tool installed successfully!"
    else
        echo "[-] $tool NOT found!"
    fi
done

echo "[*] All tools installed successfully!"

