#!/bin/bash

# ============================================================================
# BB Fucker - Otomatik Kurulum Script'i
# Platform: Linux (Kali/Ubuntu/Debian) - SADECE LINUX!
# ============================================================================
#
# NOT: Bu script SADECE Linux sistemlerde çalışır!
# Windows kullanıcıları için: WSL (Windows Subsystem for Linux) kullanın
# macOS kullanıcıları için: Homebrew ile manuel kurulum gerekir
#
# Gereksinimler:
#   - Debian/Ubuntu based Linux distro (Kali önerilir)
#   - apt-get paket yöneticisi
#   - sudo yetkileri
#   - Go 1.21+
#
# Kullanım:
#   chmod +x install.sh
#   sudo ./install.sh
# ============================================================================

set -e  # Hata durumunda dur

# ─── Platform kontrolü ───────────────────────────────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ HATA: Bu script sadece Linux'ta çalışır!"
    echo "Şu anki platform: $OSTYPE"
    echo ""
    echo "Platformunuz için:"
    echo "  - macOS: Homebrew ile tools kurun + go build çalıştırın"
    echo "  - Windows: WSL (Windows Subsystem for Linux) kullanın"
    exit 1
fi

# Go bin PATH'i hemen ekle (script boyunca geçerli olsun)
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin:/root/.local/bin"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║   ██████╗ ██████╗     ███████╗██╗   ██╗ ██████╗██╗  ██╗    ║"
echo "║   ██╔══██╗██╔══██╗    ██╔════╝██║   ██║██╔════╝██║ ██╔╝    ║"
echo "║   ██████╔╝██████╔╝    █████╗  ██║   ██║██║     █████╔╝     ║"
echo "║   ██╔══██╗██╔══██╗    ██╔══╝  ██║   ██║██║     ██╔═██╗     ║"
echo "║   ██████╔╝██████╔╝    ██║     ╚██████╔╝╚██████╗██║  ██╗    ║"
echo "║   ╚═════╝ ╚═════╝     ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝    ║"
echo "║                                                              ║"
echo "║          Otomatik Kurulum — Linux Edition v2.0              ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Renkler ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Sayaçlar
INSTALLED=0
SKIPPED=0
FAILED=0

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 1: TEMEL GEREKSİNİMLER
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}${CYAN}[1/8] Temel Gereksinimler Kontrol Ediliyor...${NC}"
echo ""

# Go version kontrolü
echo -e "${CYAN}[*] Go kurulumu kontrol ediliyor...${NC}"
if ! command -v go &>/dev/null; then
    echo -e "${RED}[✗] Go bulunamadı!${NC}"
    echo -e "${YELLOW}Kurulum için:${NC}"
    echo "    sudo apt update && sudo apt install golang-go"
    echo "    veya: https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo -e "${GREEN}[✓] Go $GO_VERSION bulundu${NC}"

# Minimum Go version kontrolü (1.21)
MIN_VERSION="1.21"
if [ "$(printf '%s\n' "$MIN_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
    echo -e "${RED}[✗] Go 1.21+ gerekli (mevcut: $GO_VERSION)${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 2: SİSTEM PAKETLERİ (apt-get)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[2/8] Sistem Paketleri Kuruluyor...${NC}"
echo ""

echo -e "${CYAN}[*] APT güncelleniyor...${NC}"
apt-get update -qq 2>/dev/null || true

# Zorunlu sistem paketleri
SYSTEM_PACKAGES="libpcap-dev git curl wget unzip"
echo -e "${CYAN}[*] Zorunlu paketler: $SYSTEM_PACKAGES${NC}"
apt-get install -y $SYSTEM_PACKAGES 2>/dev/null && \
    echo -e "${GREEN}[✓] Zorunlu sistem paketleri kuruldu${NC}" || \
    echo -e "${YELLOW}[!] Bazı sistem paketleri kurulamadı${NC}"

# nmap — Phase 3 (port scan + service detection)
echo -e "${CYAN}[*] Nmap kuruluyor...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}[✓] Nmap zaten kurulu: $(nmap --version 2>/dev/null | head -1)${NC}"
else
    apt-get install -y nmap 2>/dev/null && \
        echo -e "${GREEN}[✓] Nmap kuruldu${NC}" || \
        echo -e "${YELLOW}[!] Nmap kurulamadı — sudo apt install nmap${NC}"
fi

# whois — Phase 1 (ASN/IP lookup)
echo -e "${CYAN}[*] Whois kuruluyor...${NC}"
if command -v whois &>/dev/null; then
    echo -e "${GREEN}[✓] Whois zaten kurulu${NC}"
else
    apt-get install -y whois 2>/dev/null && \
        echo -e "${GREEN}[✓] Whois kuruldu${NC}" || \
        echo -e "${YELLOW}[!] Whois kurulamadı — sudo apt install whois${NC}"
fi

# whatweb — Phase 4 (CMS & teknoloji tespiti)
echo -e "${CYAN}[*] WhatWeb kuruluyor...${NC}"
if command -v whatweb &>/dev/null; then
    echo -e "${GREEN}[✓] WhatWeb zaten kurulu${NC}"
else
    apt-get install -y whatweb 2>/dev/null && \
        echo -e "${GREEN}[✓] WhatWeb kuruldu${NC}" || \
        (gem install whatweb 2>/dev/null && echo -e "${GREEN}[✓] WhatWeb (gem) kuruldu${NC}") || \
        echo -e "${YELLOW}[!] WhatWeb kurulamadı — sudo apt install whatweb${NC}"
fi

# wpscan — Phase 4 (WordPress scanner)
echo -e "${CYAN}[*] WPScan kuruluyor...${NC}"
if command -v wpscan &>/dev/null; then
    echo -e "${GREEN}[✓] WPScan zaten kurulu${NC}"
else
    apt-get install -y wpscan 2>/dev/null && \
        echo -e "${GREEN}[✓] WPScan kuruldu${NC}" || \
        (gem install wpscan 2>/dev/null && echo -e "${GREEN}[✓] WPScan (gem) kuruldu${NC}") || \
        echo -e "${YELLOW}[!] WPScan kurulamadı — sudo apt install wpscan${NC}"
fi

# sqlmap — Phase 6 (SQL injection)
echo -e "${CYAN}[*] SQLMap kuruluyor...${NC}"
if command -v sqlmap &>/dev/null; then
    echo -e "${GREEN}[✓] SQLMap zaten kurulu${NC}"
else
    apt-get install -y sqlmap 2>/dev/null && \
        echo -e "${GREEN}[✓] SQLMap kuruldu${NC}" || \
        echo -e "${YELLOW}[!] SQLMap kurulamadı — sudo apt install sqlmap${NC}"
fi

# python3-pip — Python araçları için
echo -e "${CYAN}[*] Python3-pip kuruluyor...${NC}"
apt-get install -y python3-pip 2>/dev/null || true

# chromium — Screenshot araçları için (gowitness/aquatone)
echo -e "${CYAN}[*] Chromium kuruluyor (screenshot desteği)...${NC}"
if command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null || command -v google-chrome &>/dev/null; then
    echo -e "${GREEN}[✓] Chromium/Chrome zaten kurulu${NC}"
else
    apt-get install -y chromium 2>/dev/null || \
        apt-get install -y chromium-browser 2>/dev/null || \
        echo -e "${YELLOW}[!] Chromium kurulamadı — screenshot özelliği çalışmayabilir${NC}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 3: GO MODÜLLERİ VE BUILD
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[3/8] Go Build...${NC}"
echo ""

echo -e "${CYAN}[*] Go modülleri indiriliyor...${NC}"
go mod tidy && echo -e "${GREEN}[✓] go mod tidy${NC}" || { echo -e "${RED}[✗] go mod tidy başarısız${NC}"; exit 1; }
go mod download && echo -e "${GREEN}[✓] go mod download${NC}" || { echo -e "${RED}[✗] go mod download başarısız${NC}"; exit 1; }

echo -e "${CYAN}[*] Binary oluşturuluyor (optimized)...${NC}"
CGO_ENABLED=1 go build -ldflags="-s -w" -o bbfucker main.go && \
    echo -e "${GREEN}[✓] Build başarılı${NC}" || \
    { echo -e "${RED}[✗] Build başarısız${NC}"; exit 1; }

chmod +x bbfucker
BINARY_SIZE=$(du -h bbfucker | cut -f1)
echo -e "${GREEN}[✓] bbfucker ($BINARY_SIZE) derlendi${NC}"

# /usr/bin altına kur — her yerden çalışsın
cp bbfucker /usr/bin/bbfucker
chmod +x /usr/bin/bbfucker
echo -e "${GREEN}[✓] bbfucker → /usr/bin/bbfucker (global)${NC}"

# /opt/bbfucker — config, wordlist ve resolver kurulumu
INSTALL_DIR="/opt/bbfucker"
mkdir -p "$INSTALL_DIR/wordlists"

# config.yaml kopyala ve içindeki relative yolları absolute yap
cp config.yaml "$INSTALL_DIR/config.yaml"
sed -i "s|\"resolvers.txt\"|\"$INSTALL_DIR/resolvers.txt\"|g" "$INSTALL_DIR/config.yaml"
sed -i "s|\"wordlists/|\"$INSTALL_DIR/wordlists/|g" "$INSTALL_DIR/config.yaml"
echo -e "${GREEN}[✓] config.yaml → $INSTALL_DIR/config.yaml${NC}"

# resolvers.txt kopyala (oluşturulduysa)
[ -f resolvers.txt ] && cp resolvers.txt "$INSTALL_DIR/resolvers.txt" && \
    echo -e "${GREEN}[✓] resolvers.txt → $INSTALL_DIR/resolvers.txt${NC}"

# wordlists kopyala (oluşturulduysa)
if [ -d wordlists ] && [ "$(ls -A wordlists 2>/dev/null)" ]; then
    cp -r wordlists/. "$INSTALL_DIR/wordlists/"
    echo -e "${GREEN}[✓] wordlists/ → $INSTALL_DIR/wordlists/${NC}"
fi

chmod -R 755 "$INSTALL_DIR"
echo -e "${GREEN}[✓] Kurulum dizini hazır: $INSTALL_DIR${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 4: GO ARAÇLARI (go install)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[4/8] Go Araçları Kuruluyor...${NC}"
echo ""

install_go_tool() {
    local name=$1
    local pkg=$2
    local bin_name_override=${3:-}
    local bin_name

    bin_name=$(basename "$pkg" | cut -d@ -f1)
    # v2, v3 gibi versiyon suffix'i varsa bir üst dizin adını kullan
    if [[ "$bin_name" =~ ^v[0-9]+$ ]]; then
        bin_name=$(echo "${pkg%@*}" | rev | cut -d/ -f2 | rev)
    fi
    [ -n "$bin_name_override" ] && bin_name="$bin_name_override"

    # Zaten kuruluysa atla
    if command -v "$bin_name" &>/dev/null; then
        echo -e "${GREEN}[✓] $name zaten kurulu${NC}"
        ((SKIPPED++)) || true
        return 0
    fi

    echo -e "${CYAN}[*] $name kuruluyor...${NC}"
    if go install "$pkg" 2>&1 | tail -3; then
        export PATH="$PATH:$GOPATH/bin"
        sleep 1
        if command -v "$bin_name" &>/dev/null; then
            echo -e "${GREEN}[✓] $name kuruldu → $(which $bin_name)${NC}"
            ((INSTALLED++)) || true
            return 0
        fi
    fi

    # 2. deneme
    echo -e "${YELLOW}[!] $name tekrar deneniyor...${NC}"
    go clean -cache 2>/dev/null || true
    go install "$pkg" 2>&1 | tail -3 || true
    sleep 1
    export PATH="$PATH:$GOPATH/bin"

    if command -v "$bin_name" &>/dev/null; then
        echo -e "${GREEN}[✓] $name kuruldu (2. deneme)${NC}"
        ((INSTALLED++)) || true
    else
        echo -e "${RED}[✗] $name kurulamadı — go install $pkg${NC}"
        ((FAILED++)) || true
    fi
}

# ─── Phase 1: Passive Intelligence ───────────────────────────────────────────
echo -e "${BOLD}--- Phase 1: Passive Intelligence ---${NC}"
install_go_tool "Subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "ASNmap"      "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
install_go_tool "Assetfinder" "github.com/tomnomnom/assetfinder@latest"

# Amass (opsiyonel, büyük binary)
echo -e "${CYAN}[*] Amass kuruluyor (büyük binary, sabırlı olun)...${NC}"
if command -v amass &>/dev/null; then
    echo -e "${GREEN}[✓] Amass zaten kurulu${NC}"
else
    go install github.com/owasp-amass/amass/v4/...@latest 2>/dev/null && \
        echo -e "${GREEN}[✓] Amass kuruldu${NC}" || \
        echo -e "${YELLOW}[!] Amass opsiyonel — kurulum başarısız${NC}"
fi

# Findomain (Rust binary — pre-built release)
if command -v findomain &>/dev/null; then
    echo -e "${GREEN}[✓] Findomain zaten kurulu${NC}"
else
    echo -e "${CYAN}[*] Findomain kuruluyor...${NC}"
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
        curl -sLo /tmp/findomain "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" 2>/dev/null && \
            chmod +x /tmp/findomain && \
            mv /tmp/findomain /usr/local/bin/findomain && \
            echo -e "${GREEN}[✓] Findomain kuruldu${NC}" || \
            echo -e "${YELLOW}[!] Findomain opsiyonel — kurulum başarısız${NC}"
    elif [ "$ARCH" = "aarch64" ]; then
        curl -sLo /tmp/findomain "https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64" 2>/dev/null && \
            chmod +x /tmp/findomain && \
            mv /tmp/findomain /usr/local/bin/findomain && \
            echo -e "${GREEN}[✓] Findomain kuruldu (aarch64)${NC}" || \
            echo -e "${YELLOW}[!] Findomain opsiyonel — kurulum başarısız${NC}"
    else
        echo -e "${YELLOW}[!] Findomain: desteklenmeyen mimari ($ARCH)${NC}"
    fi
fi

# ─── Phase 2: DNS Resolution ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Phase 2: DNS Resolution ---${NC}"
install_go_tool "Puredns" "github.com/d3mondev/puredns/v2@latest"
install_go_tool "DNSx"    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "Anew"    "github.com/tomnomnom/anew@latest"

# ─── Phase 3: Infrastructure ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Phase 3: Infrastructure ---${NC}"
install_go_tool "Naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "HTTPx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "FFUF"  "github.com/ffuf/ffuf/v2@latest"

# RustScan — ana port tarayıcı
if command -v rustscan &>/dev/null; then
    echo -e "${GREEN}[✓] RustScan zaten kurulu: $(rustscan --version 2>/dev/null | head -1)${NC}"
else
    echo -e "${CYAN}[*] RustScan kuruluyor...${NC}"
    ARCH=$(uname -m)
    RS_URL=""
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
        RS_URL="https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb"
    elif [ "$ARCH" = "aarch64" ]; then
        RS_URL="https://github.com/RustScan/RustScan/releases/latest/download/rustscan_arm64.deb"
    fi
    if [ -n "$RS_URL" ]; then
        if curl -sLo /tmp/rustscan.deb "$RS_URL" 2>/dev/null; then
            dpkg -i /tmp/rustscan.deb 2>/dev/null && \
                echo -e "${GREEN}[✓] RustScan kuruldu${NC}" || \
                echo -e "${YELLOW}[!] RustScan deb kurulum başarısız — cargo ile dene: cargo install rustscan${NC}"
            rm -f /tmp/rustscan.deb
        else
            echo -e "${YELLOW}[!] RustScan indirilemedi — cargo install rustscan${NC}"
        fi
    else
        echo -e "${YELLOW}[!] RustScan: desteklenmeyen mimari ($ARCH) — cargo install rustscan${NC}"
    fi
fi

# ─── Phase 4: Web Probing & Vuln Scan ────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Phase 4: Web Probing & Vuln Scan ---${NC}"
install_go_tool "Nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "Subzy"  "github.com/PentestPad/subzy@latest"
install_go_tool "Notify" "github.com/projectdiscovery/notify/cmd/notify@latest"

# Nuclei templates güncelle
echo -e "${CYAN}[*] Nuclei templates güncelleniyor...${NC}"
nuclei -ut 2>/dev/null && \
    echo -e "${GREEN}[✓] Nuclei templates güncellendi${NC}" || \
    echo -e "${YELLOW}[!] Nuclei templates güncellenemedi${NC}"

# ─── Phase 5: Content Discovery ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Phase 5: Content Discovery ---${NC}"
install_go_tool "Katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "Gau"    "github.com/lc/gau/v2/cmd/gau@latest"

# ─── Phase 6: Parameter Fuzzing ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Phase 6: Parameter Fuzzing ---${NC}"
install_go_tool "Dalfox"    "github.com/hahwul/dalfox/v2@latest"
install_go_tool "GF"        "github.com/tomnomnom/gf@latest"
install_go_tool "Qsreplace" "github.com/tomnomnom/qsreplace@latest"

# ─── Screenshot Araçları ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Screenshot Araçları ---${NC}"
install_go_tool "Gowitness" "github.com/sensepost/gowitness@latest"

# Aquatone (pre-built release)
if command -v aquatone &>/dev/null; then
    echo -e "${GREEN}[✓] Aquatone zaten kurulu${NC}"
else
    echo -e "${CYAN}[*] Aquatone kuruluyor...${NC}"
    AQUA_URL="https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64_1.7.0.zip"
    if curl -sLo /tmp/aquatone.zip "$AQUA_URL" 2>/dev/null; then
        cd /tmp && unzip -o aquatone.zip aquatone 2>/dev/null && \
            chmod +x aquatone && mv aquatone /usr/local/bin/aquatone && \
            echo -e "${GREEN}[✓] Aquatone kuruldu${NC}" || \
            echo -e "${YELLOW}[!] Aquatone opsiyonel — kurulum başarısız${NC}"
        rm -f /tmp/aquatone.zip
        cd - >/dev/null
    else
        echo -e "${YELLOW}[!] Aquatone opsiyonel — indirilemedi${NC}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 5: PYTHON ARAÇLARI (pipx/pip3)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[5/8] Python Araçları Kuruluyor...${NC}"
echo ""

# pipx kurulumu
echo -e "${CYAN}[*] pipx kontrol ediliyor...${NC}"
if ! command -v pipx &>/dev/null; then
    apt-get install -y pipx 2>/dev/null || pip3 install --break-system-packages pipx 2>/dev/null || true
    pipx ensurepath 2>/dev/null || true
    export PATH="$PATH:$HOME/.local/bin:/root/.local/bin"
fi
if command -v pipx &>/dev/null; then
    echo -e "${GREEN}[✓] pipx hazır${NC}"
else
    echo -e "${YELLOW}[!] pipx kurulamadı — pip3 kullanılacak${NC}"
fi

install_pip_tool() {
    local name=$1
    local pkg=$2
    local binary=${3:-$pkg}

    export PATH="$PATH:$HOME/.local/bin:/root/.local/bin"

    if command -v "$binary" &>/dev/null; then
        echo -e "${GREEN}[✓] $name zaten kurulu${NC}"
        ((SKIPPED++)) || true
        return 0
    fi

    echo -e "${CYAN}[*] $name kuruluyor...${NC}"

    # pipx ile dene
    if command -v pipx &>/dev/null; then
        pipx uninstall "$pkg" &>/dev/null 2>&1 || true
        if pipx install "$pkg" 2>&1 | tail -3; then
            hash -r 2>/dev/null || true
            sleep 1
            if command -v "$binary" &>/dev/null; then
                echo -e "${GREEN}[✓] $name kuruldu (pipx)${NC}"
                ((INSTALLED++)) || true
                return 0
            fi
        fi
    fi

    # pip3 fallback
    if pip3 install --break-system-packages "$pkg" 2>&1 | tail -3; then
        sleep 1
        if command -v "$binary" &>/dev/null; then
            echo -e "${GREEN}[✓] $name kuruldu (pip3)${NC}"
            ((INSTALLED++)) || true
            return 0
        fi
    fi

    echo -e "${RED}[✗] $name kurulamadı — pipx install $pkg${NC}"
    ((FAILED++)) || true
}

# wafw00f — Phase 4 (WAF detection)
install_pip_tool "wafw00f" "wafw00f" "wafw00f"

# waymore — Phase 5 (URL gathering)
install_pip_tool "Waymore" "waymore" "waymore"

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 6: GF PATTERNS & WORDLISTS
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[6/8] GF Patterns & Wordlists...${NC}"
echo ""

# GF Patterns
echo -e "${CYAN}[*] GF pattern'leri kuruluyor...${NC}"
GF_DIR="$HOME/.gf"
mkdir -p "$GF_DIR"
if [ ! -d "$GF_DIR/patterns/.git" ]; then
    git clone --quiet https://github.com/1ndianl33t/Gf-Patterns "$GF_DIR/patterns" 2>/dev/null && \
        cp "$GF_DIR/patterns"/*.json "$GF_DIR/" 2>/dev/null && \
        echo -e "${GREEN}[✓] GF patterns kuruldu${NC}" || \
        echo -e "${YELLOW}[!] GF patterns opsiyonel — indirilemedi${NC}"
else
    cd "$GF_DIR/patterns" && git pull --quiet 2>/dev/null && cp ./*.json "$GF_DIR/" 2>/dev/null; cd - >/dev/null
    echo -e "${GREEN}[✓] GF patterns güncellendi${NC}"
fi

# DNS Resolvers — config.yaml'daki resolvers: "resolvers.txt" için
echo -e "${CYAN}[*] DNS resolver listesi oluşturuluyor...${NC}"
cat > resolvers.txt << 'EOF'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
185.228.168.9
185.228.169.9
76.76.19.19
76.223.122.150
94.140.14.14
94.140.15.15
EOF
echo -e "${GREEN}[✓] resolvers.txt oluşturuldu (16 public DNS)${NC}"

# SecLists
echo -e "${CYAN}[*] SecLists kontrol ediliyor...${NC}"
mkdir -p wordlists
if [ -d "/usr/share/seclists" ]; then
    echo -e "${GREEN}[✓] SecLists mevcut: /usr/share/seclists${NC}"
    ln -sf /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt wordlists/dns_bruteforce.txt 2>/dev/null
    ln -sf /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt wordlists/directories.txt 2>/dev/null
    ln -sf /usr/share/seclists/Discovery/Web-Content/common.txt wordlists/common.txt 2>/dev/null
else
    echo -e "${CYAN}[*] SecLists kuruluyor...${NC}"
    apt-get install -y seclists 2>/dev/null && \
        echo -e "${GREEN}[✓] SecLists kuruldu${NC}" || \
        echo -e "${YELLOW}[!] SecLists kurulamadı — git clone https://github.com/danielmiessler/SecLists${NC}"
    # Linkle
    if [ -d "/usr/share/seclists" ]; then
        ln -sf /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt wordlists/dns_bruteforce.txt 2>/dev/null
        ln -sf /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt wordlists/directories.txt 2>/dev/null
        ln -sf /usr/share/seclists/Discovery/Web-Content/common.txt wordlists/common.txt 2>/dev/null
    fi
fi

# Temel DNS bruteforce wordlist (fallback)
if [ ! -f "wordlists/dns_bruteforce.txt" ]; then
    echo -e "${CYAN}[*] Temel DNS wordlist oluşturuluyor...${NC}"
    cat > wordlists/dns_bruteforce.txt << 'EOF'
www
api
mail
ftp
dev
staging
test
admin
portal
vpn
cdn
static
assets
img
images
mobile
app
beta
alpha
prod
production
old
legacy
backup
db
database
auth
login
dashboard
panel
webmail
smtp
pop
imap
ns1
ns2
mx
shop
store
blog
news
docs
help
support
status
monitor
git
gitlab
jenkins
jira
confluence
wiki
intranet
corp
internal
EOF
    echo -e "${GREEN}[✓] Temel dns_bruteforce.txt oluşturuldu${NC}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 7: PATH & DİZİN YAPISI
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[7/8] PATH & Dizin Yapısı...${NC}"
echo ""

# results/ dizini binary'nin çalıştırıldığı yerde otomatik oluşur — burada oluşturmaya gerek yok

# PATH kalıcı olarak ekle
GOBIN="$GOPATH/bin"
PATH_LINE="export PATH=\$PATH:$GOBIN"
LOCAL_BIN_LINE="export PATH=\$PATH:\$HOME/.local/bin"

for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$RC" ]; then
        if ! grep -qF "$GOBIN" "$RC" 2>/dev/null; then
            echo "" >> "$RC"
            echo "# BBFucker — Go binaries" >> "$RC"
            echo "$PATH_LINE" >> "$RC"
            echo -e "${GREEN}[✓] Go PATH → $RC${NC}"
        fi
        if ! grep -q '.local/bin' "$RC" 2>/dev/null; then
            echo "$LOCAL_BIN_LINE" >> "$RC"
            echo -e "${GREEN}[✓] Local bin PATH → $RC${NC}"
        fi
    fi
done

export PATH="$PATH:$GOBIN:$HOME/.local/bin"

# Config kontrolü
if [ -f "config.yaml" ]; then
    echo -e "${GREEN}[✓] config.yaml mevcut${NC}"
else
    echo -e "${RED}[✗] config.yaml bulunamadı!${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# BÖLÜM 8: DOĞRULAMA & RAPOR
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}[8/8] Araç Durumu Doğrulanıyor...${NC}"
echo ""

# Araç kontrol fonksiyonu
check_tool() {
    local label=$1
    local bin=$2
    local install_hint=$3
    if command -v "$bin" &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $label"
        return 0
    else
        echo -e "  ${RED}[✗]${NC} $label ${YELLOW}← $install_hint${NC}"
        return 1
    fi
}

echo -e "${BOLD}Phase 1 — Passive Intelligence:${NC}"
check_tool "Subfinder     (subdomain enum)"     subfinder   "go install subfinder"
check_tool "ASNmap        (ASN lookup)"          asnmap      "go install asnmap"
check_tool "Assetfinder   (passive recon)"       assetfinder "go install assetfinder"
check_tool "Amass         (passive recon)"       amass       "go install amass (opsiyonel)"
check_tool "Findomain     (passive recon)"       findomain   "curl binary (opsiyonel)"
check_tool "Whois         (WHOIS lookup)"        whois       "apt install whois"

echo ""
echo -e "${BOLD}Phase 2 — DNS Resolution:${NC}"
check_tool "Puredns       (DNS bruteforce)"      puredns     "go install puredns"
check_tool "DNSx          (DNS probe)"           dnsx        "go install dnsx"
check_tool "Anew          (dedup utility)"       anew        "go install anew"

echo ""
echo -e "${BOLD}Phase 3 — Infrastructure:${NC}"
check_tool "RustScan      (port scan)"           rustscan    "https://github.com/RustScan/RustScan/releases"
check_tool "Naabu         (port scan fallback)"  naabu       "go install naabu"
check_tool "Nmap          (service detect)"      nmap        "apt install nmap"
check_tool "HTTPx         (web probe)"           httpx       "go install httpx"
check_tool "FFUF          (dir fuzzing)"         ffuf        "go install ffuf"

echo ""
echo -e "${BOLD}Phase 4 — Web Probing & Vuln:${NC}"
check_tool "Nuclei        (vuln scan)"           nuclei      "go install nuclei"
check_tool "Subzy         (takeover)"            subzy       "go install subzy"
check_tool "wafw00f       (WAF detect)"          wafw00f     "pipx install wafw00f"
check_tool "WhatWeb       (CMS detect)"          whatweb     "apt install whatweb"
check_tool "WPScan        (WP scanner)"          wpscan      "apt install wpscan"
check_tool "Notify        (notification)"        notify      "go install notify"

echo ""
echo -e "${BOLD}Phase 5 — Content Discovery:${NC}"
check_tool "Katana        (crawler)"             katana      "go install katana"
check_tool "Gau           (URL gather)"          gau         "go install gau"
check_tool "Waymore       (URL gather)"          waymore     "pipx install waymore"

echo ""
echo -e "${BOLD}Phase 6 — Parameter Fuzzing:${NC}"
check_tool "Dalfox        (XSS scan)"            dalfox      "go install dalfox"
check_tool "GF            (pattern filter)"      gf          "go install gf"
check_tool "Qsreplace     (param replace)"       qsreplace   "go install qsreplace"
check_tool "SQLMap        (SQL injection)"       sqlmap      "apt install sqlmap"

echo ""
echo -e "${BOLD}Screenshot:${NC}"
check_tool "Gowitness     (screenshot)"          gowitness   "go install gowitness"
check_tool "Aquatone      (screenshot)"          aquatone    "binary release (opsiyonel)"

# ─── Final Tool Count ────────────────────────────────────────────────────────
echo ""

ALL_TOOLS=("subfinder" "asnmap" "assetfinder" "amass" "findomain" "whois"
           "puredns" "dnsx" "anew"
           "rustscan" "naabu" "nmap" "httpx" "ffuf"
           "nuclei" "subzy" "wafw00f" "whatweb" "wpscan" "notify"
           "katana" "gau" "waymore"
           "dalfox" "gf" "qsreplace" "sqlmap"
           "gowitness" "aquatone")

CRITICAL_TOOLS=("subfinder" "dnsx" "httpx" "rustscan" "nuclei" "katana" "gau" "ffuf" "dalfox" "gf")

working=0
total=${#ALL_TOOLS[@]}
critical_ok=0
critical_total=${#CRITICAL_TOOLS[@]}
missing_critical=()

for tool in "${ALL_TOOLS[@]}"; do
    command -v "$tool" &>/dev/null && ((working++)) || true
done

for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ((critical_ok++)) || true
    else
        missing_critical+=("$tool")
    fi
done

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [ $critical_ok -eq $critical_total ]; then
    echo -e "${GREEN}✅ Kritik araçlar: $critical_ok/$critical_total — TAMAM${NC}"
else
    echo -e "${RED}⚠️  Kritik araçlar: $critical_ok/$critical_total — Eksik: ${missing_critical[*]}${NC}"
fi
echo -e "${CYAN}📊 Toplam araçlar: $working/$total kurulu${NC}"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   KURULUM TAMAMLANDI! ✓                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Kullanım:${NC}"
echo -e "  ${YELLOW}bbfucker -d example.com -v${NC}                # Verbose tarama"
echo -e "  ${YELLOW}bbfucker -d example.com -threads 50${NC}       # Hızlı tarama"
echo -e "  ${YELLOW}bbfucker -d example.com -deep${NC}             # Derin tarama"
echo -e "  ${YELLOW}bbfucker -d example.com -mode recon${NC}       # Sadece recon"
echo -e "  ${YELLOW}bbfucker -d example.com -mode full${NC}        # Tam tarama"
echo ""
echo -e "${CYAN}Parametreler:${NC}"
echo -e "  -d domain          Hedef domain (zorunlu)"
echo -e "  -config file       Config dosyası (default: config.yaml)"
echo -e "  -v                 Verbose mode"
echo -e "  -threads N         Worker sayısı (default: config'den)"
echo -e "  -deep              Derin tarama modu"
echo -e "  -phase N           Sadece belirli phase (1-6)"
echo -e "  -mode MODE         full | recon | web | p3 | 1,2,3 | 1-4"
echo ""
echo -e "${CYAN}Çıktılar:${NC}"
echo -e "  Taramayı hangi dizinden çalıştırırsan orada results/ oluşur:"
echo -e "  results/<domain>/<timestamp>/"
echo -e "    ├── report.html     # Tarayıcıda aç"
echo -e "    ├── report.json     # JSON formatı"
echo -e "    ├── subdomains.txt"
echo -e "    ├── urls.txt"
echo -e "    └── summary.txt"
echo ""
echo -e "${YELLOW}Bu terminal penceresini kapatıp yeni bir terminal aç.${NC}"
echo ""
echo -e "${GREEN}Happy Hacking! ⚡${NC}"
echo ""
