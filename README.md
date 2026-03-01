# bbFucker — Go Bug Bounty Recon Pipeline

Kali Linux / Ubuntu için yazılmış, 6 fazlı otomatik bug bounty keşif aracı.

---

## Özellikler

- **6 faz pipeline** — Passive → DNS → Infra → Web Probe → Content → Fuzz
- **WAF-aware** — Cloudflare/Akamai/Imperva tespiti, otomatik stealth mod
- **Hata toleranslı** — Bir faz çökse pipeline devam eder
- **Araç bağımsız** — Eksik araç varsa fallback mekanizması devreye girer
- **Temiz çıktı** — Boş dosya oluşmaz, gürültülü URL (feeds, static asset) filtrelenir

---

## Kurulum

```bash
git clone https://github.com/kullanici_adi/bbfucker.git
cd bbfucker
chmod +x install.sh && ./install.sh
```

### Manuel Build

```bash
go build -ldflags="-s -w" -o bbfucker main.go
```

### Araç Kurulumları (Linux)

```bash
# Go araçları
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/gf@latest
go install github.com/haccer/subjack@latest
go install github.com/tomnomnom/assetfinder@latest

# Sistem araçları
sudo apt install nmap wafw00f whatweb wpscan sqlmap -y
```

---

## Kullanım

```bash
# Temel tarama
./bbfucker -d hedef.com

# Detaylı çıktı
./bbfucker -d hedef.com -v

# Full tarama
./bbfucker -d hedef.com -mode full -v
```

### Parametreler

```
-d string      Hedef domain (zorunlu)
-mode string   Tarama modu (default: full)
-v             Verbose mod
-config string Config dosyası (default: config.yaml)
-threads int   Worker sayısı (default: config.yaml max_workers)
-o string      Çıktı klasörü (default: results/)
```

---

## Pipeline Fazları

```
Phase 1 — Passive Intelligence
  subfinder, assetfinder, crt.sh, HackerTarget, AlienVault, asnmap

Phase 2 — DNS Resolution & Brute-force
  puredns resolve → dnsx fallback
  puredns bruteforce (wordlist) → dnsx fallback

Phase 3 — Infrastructure
  ffuf vhost discovery (baseline calibration ile false-positive onleme)
  nmap -sT/-sS -sV -T2 stealth web port scan

Phase 4 — Web Probing
  httpx probing → Go HTTP fallback
  nuclei CVE/misconfig taramasi (WAF varsa stealth mod, IsKilled kontrol)
  subjack takeover tespiti
  wafw00f + whatweb CMS/WAF analizi

Phase 5 — Content Analysis
  gau + katana URL toplama
  JS dosyasi kesfi + endpoint cikarimi
  secret/API key taramasi
  URL kalite filtresi (feeds, static asset temizligi)

Phase 6 — Parameter Fuzzing & Vuln Testing
  URL param kesfi (blocklist ile gurultu filtresi)
  GF pattern filtreleme (xss, lfi, sqli, ssrf, redirect)
  dalfox XSS taramasi (WAF varsa WAF-evasion + IsKilled kontrol)
  sqlmap SQLi testi
  ffuf directory/file fuzzing
```

---

## Çıktılar

`results/[domain]/[timestamp]/` klasörüne kaydedilir:

```
subdomains.txt       — Bulunan subdomain'ler
live_hosts.txt       — Aktif hostlar [status code]
urls.txt             — Toplanan URL'ler (filtrelenmiş)
ports.txt            — Açık portlar (host:port - state)
services.txt         — Servis tespitleri (host:port - servis versiyon)
js_files.txt         — JavaScript dosyaları
endpoints.txt        — JS endpoint'leri
parameters.txt       — Keşfedilen URL parametreleri
vulnerabilities.txt  — Bulunan açıklar
report.html          — HTML rapor
report.json          — JSON rapor
scan.log             — Structured log (JSON)
summary.txt          — Özet istatistikler
```

---

## WAF Koruması

Hedef WAF kullanıyorsa araç otomatik olarak:

- nuclei → `-c 3 -rate-limit 15` ile düşük hız
- dalfox → `--waf-evasion --delay <ms>` ile evasion modu
- 3+ blok yaşanırsa o host tamamen tarama dışı bırakılır (WAFGuard)

---

## Konfigürasyon

`config.yaml` ile tüm fazlar, araçlar ve performans ayarlanabilir.

Temel ayarlar:

```yaml
settings:
  max_workers: 20    # Goroutine sayısı
  timeout: 10        # Request timeout (saniye)

phase4_web_probing:
  nuclei:
    severity: "critical,high,medium"
    tags: "cve,misconfig,exposed-panel,tech,vuln"

phase6_parameter_fuzzing:
  xss_testing:
    dalfox:
      waf_evasion: true
```

---

## Gereksinimler

- Go 1.21+
- Linux (Kali/Ubuntu/Debian önerilir)
- `resolvers.txt` — puredns için gerekli

```bash
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```

---

## Yasal Uyarı

Bu araç yalnızca **izin verilen sistemlerde** ve **bug bounty programlarında** kullanılmak üzere geliştirilmiştir. İzinsiz sistemlere kullanım yasaldışıdır. Kullanıcı tüm sorumluluğu kabul eder.

---

## Lisans

MIT
