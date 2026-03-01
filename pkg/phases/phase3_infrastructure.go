package phases

import (
"bbfucker/pkg/config"
"bbfucker/pkg/logger"
"bufio"
"bytes"
"context"
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"os/exec"
"strconv"
"strings"
"time"

"github.com/fatih/color"
)

// ============================================================================
// Phase 3: Infrastructure & VHost Analysis
// ============================================================================

type Phase3Infrastructure struct {
cfg *config.Config
}

func NewPhase3Infrastructure() *Phase3Infrastructure {
return &Phase3Infrastructure{}
}

func (p *Phase3Infrastructure) Name() string {
return "Phase 3: Infrastructure & VHost Analysis"
}

func (p *Phase3Infrastructure) Description() string {
return "Virtual Host discovery (FFUF)"
}

func (p *Phase3Infrastructure) IsEnabled(cfg *config.Config) bool {
return cfg.Phase3Infrastructure.Enabled
}

func (p *Phase3Infrastructure) Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error) {
p.cfg = cfg
startTime := time.Now()
log := logger.Default().With("phase", "3-infra", "domain", input.Domain)

color.Cyan("\n[PHASE 3] %s", p.Name())
color.Cyan("═══════════════════════════════════════════════════════════")

p.checkInfrastructureToolsAvailability()

output := &PhaseOutput{
PhaseName: p.Name(),
OpenPorts: make([]PortInfo, 0),
Services:  make([]ServiceInfo, 0),
Statistics: Statistics{
ToolsUsed: make([]string, 0),
Extra:     make(map[string]int),
},
Extra: make(map[string]interface{}),
}

// Step 3.1: VHost Discovery (FFUF)
if cfg.Phase3Infrastructure.VHostDiscovery.Enabled {
color.Yellow("\n[*] Step 3.1: Virtual Host Discovery (FFUF)")
if _, err := exec.LookPath("ffuf"); err != nil {
color.Yellow("  [!] ffuf kurulu değil — vhost discovery atlandı")
color.Yellow("      Kurulum: go install github.com/ffuf/ffuf/v2@latest")
} else {
vhosts := p.discoverVHosts(ctx, input.ResolvedDomains)
output.Subdomains = append(output.Subdomains, vhosts...)
output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "ffuf")
output.Statistics.Extra["vhosts"] = len(vhosts)
color.Green("[✓] Discovered %d virtual hosts", len(vhosts))
}
}

// Step 3.2: Port Scan (RustScan + Nmap)
color.Yellow("\n[*] Step 3.2: Port Scan (RustScan → Nmap -sV)")
if len(input.ResolvedDomains) > 0 {
	ports := p.rustScanPortScan(ctx, input.ResolvedDomains)
	output.OpenPorts = append(output.OpenPorts, ports...)
	// -sV ile gelen servis bilgilerini services.txt için ServiceInfo'ya aktar
	for _, p2 := range ports {
	if p2.Service != "" {
		output.Services = append(output.Services, ServiceInfo{
			Host:    p2.Host,
			Port:    p2.Port,
			Name:    p2.Service,
			Service: p2.Service,
			Version: p2.Version,
		})
	}
}
output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "rustscan")
output.Statistics.Extra["open_ports"] = len(ports)
output.Statistics.Extra["services"] = len(output.Services)
if len(output.Services) > 0 {
	color.Green("[✓] Found %d open web ports, %d servis tespit edildi", len(ports), len(output.Services))
} else {
	color.Green("[✓] Found %d open web ports", len(ports))
}
} else {
color.Yellow("  [!] Resolve edilmiş host yok — port scan atlandı")
}

output.Statistics.TotalItems = len(output.Subdomains) + len(output.OpenPorts)
output.Statistics.Duration = time.Since(startTime).Seconds()

log.Infof("Phase 3 tamamlandi: %d vhost, %d port, %d servis, %.2fs", len(output.Subdomains), len(output.OpenPorts), len(output.Services), output.Statistics.Duration)
color.Green("\n[\u2713] Phase 3 Complete: %d vhosts, %d open ports, %d services", len(output.Subdomains), len(output.OpenPorts), len(output.Services))
color.Cyan("═══════════════════════════════════════════════════════════\n")

return output, nil
}

// ============================================================================
// VHost Discovery
// ============================================================================

// baselineResponseSize hedef sunucuya rastgele bir path ile istek atarak
// "normal 404" yanıtının Content-Length değerini döndürür.
// ffuf bunu -fs ile filtre olarak kullanacak.
func (p *Phase3Infrastructure) baselineResponseSize(targetURL string) int64 {
client := &http.Client{Timeout: 10 * time.Second}
probe := targetURL + "/bbfucker_baseline_probe_" + strconv.FormatInt(time.Now().UnixNano(), 36)
resp, err := client.Get(probe)
if err != nil {
return -1
}
defer resp.Body.Close()
body, err := io.ReadAll(io.LimitReader(resp.Body, SmallBodyLimit))
if err != nil {
return -1
}
return int64(len(body))
}

func (p *Phase3Infrastructure) discoverVHosts(ctx context.Context, hosts []string) []string {
if len(hosts) == 0 {
return []string{}
}

target := "http://" + hosts[0]
domain := strings.TrimPrefix(hosts[0], "www.")

color.Cyan("  [>] Hedef: %s", target)

wordlist := p.findVHostWordlist()
if wordlist == "" {
color.Yellow("  [!] VHost wordlist bulunamadı, atlıyor")
color.Yellow("      Beklenen: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
return []string{}
}

color.Cyan("  [>] Wordlist: %s", wordlist)

// Baseline yanıt boyutunu ölç — bu boyuttaki yanıtlar false-positive
baseSize := p.baselineResponseSize(target)
if baseSize >= 0 {
color.Cyan("  [>] Baseline response size: %d bytes (false-positive filtresi)", baseSize)
} else {
color.Yellow("  [!] Baseline ölçülemedi — ffuf --calibrate ile devam ediliyor")
}

tmpFFUFOut, err := os.CreateTemp("", "bbfucker_ffuf_*.json")
if err != nil {
color.Yellow("  [!] Temp dosyası oluşturulamadı: %v", err)
return []string{}
}
tmpFFUFOut.Close()
defer os.Remove(tmpFFUFOut.Name())

// ffuf için bağımsız 2 dakika timeout — pipeline context'ten ayrı
ffufCtx, ffufCancel := context.WithTimeout(ctx, 120*time.Second)
defer ffufCancel()

args := []string{
"-u", target,
"-H", fmt.Sprintf("Host: FUZZ.%s", domain),
"-w", wordlist,
"-mc", "200,301,302,403",
"-t", "20",        // thread sayısı
"-timeout", "8",  // per-request timeout (saniye)
"-maxtime", "110", // toplam çalışma süresi (saniye) — context'ten 10s önce dur
"-s",
"-o", tmpFFUFOut.Name(),
"-of", "json",
}

// Baseline alındıysa -fs ile filtrele, alınamadıysa --calibrate kullan
if baseSize >= 0 {
args = append(args, "-fs", strconv.FormatInt(baseSize, 10))
} else {
args = append(args, "--calibrate")
}

cmd := exec.CommandContext(ffufCtx, "ffuf", args...)
cmd.Stdout = nil // terminal'e basmasın
cmd.Stderr = nil
if err := cmd.Run(); err != nil {
if ffufCtx.Err() != nil {
	color.Yellow("  [!] ffuf 2 dakika limitine ulaştı — devam ediliyor")
} else {
	logger.Debugf("ffuf vhost discovery başarısız: %v", err)
}
return []string{}
}

ffufData, err := os.ReadFile(tmpFFUFOut.Name())
if err != nil || len(ffufData) == 0 {
return []string{}
}

var ffufOut struct {
Results []struct {
Input struct {
FUZZ string `json:"FUZZ"`
} `json:"input"`
Status int `json:"status"`
} `json:"results"`
}

if err := json.Unmarshal(ffufData, &ffufOut); err != nil {
return []string{}
}

var vhosts []string
for _, r := range ffufOut.Results {
if r.Input.FUZZ != "" {
vhost := r.Input.FUZZ + "." + domain
vhosts = append(vhosts, vhost)
if p.cfg.Output.Verbose {
color.Green("  [vhost] %s [%d]", vhost, r.Status)
}
}
}
return vhosts
}

// ============================================================================
// RustScan → Nmap Port Scan
// ============================================================================

// webPorts — taranacak portlar: yalnızca web uygulamalarında anlamlı portlar
const webPorts = "80,443,8000,8008,8080,8443,3000,4443,5000,8888,9090,9443,10000"

// webPortSet — hızlı lookup için port numaraları seti
var webPortSet = map[int]bool{
	80: true, 443: true, 8000: true, 8008: true, 8080: true,
	8443: true, 3000: true, 4443: true, 5000: true, 8888: true,
	9090: true, 9443: true, 10000: true,
}

// rustScanPortScan: RustScan ile hızlı port keşfi, ardından nmap -sV ile servis tespiti.
// RustScan yoksa doğrudan nmap fallback'e geçer.
func (p *Phase3Infrastructure) rustScanPortScan(ctx context.Context, hosts []string) []PortInfo {
	if len(hosts) == 0 {
		return nil
	}

	// Timeout: host başına 15s, max 8 dakika
	scanTimeout := time.Duration(len(hosts)) * 15 * time.Second
	if scanTimeout > 8*time.Minute {
		scanTimeout = 8 * time.Minute
	}
	scanCtx, scanCancel := context.WithTimeout(ctx, scanTimeout)
	defer scanCancel()

	// RustScan var mı?
	haveRustScan := false
	if _, err := exec.LookPath("rustscan"); err == nil {
		haveRustScan = true
	}
	haveNmap := false
	if _, err := exec.LookPath("nmap"); err == nil {
		haveNmap = true
	}

	if !haveRustScan && !haveNmap {
		color.Yellow("  [!] rustscan ve nmap bulunamadı — port scan atlandı")
		color.Yellow("      RustScan: https://github.com/RustScan/RustScan/releases")
		color.Yellow("      Nmap: apt install nmap")
		return nil
	}

	var openPorts []PortInfo // rustscan'dan gelen ham sonuçlar

	// ── Adım 1: RustScan ile hızlı port keşfi ─────────────────────────────────
	if haveRustScan {
		color.Cyan("  [>] RustScan: %d host, portlar: %s (max %s)", len(hosts), webPorts, scanTimeout.Round(time.Second))

		rstArgs := []string{
			"-a", strings.Join(hosts, ","),
			"-p", webPorts,
			"--ulimit", "5000",
			"--timeout", "2000", // ms cinsinden per-port connect timeout
			"--tries", "1",
			"-g",              // greppable: "1.2.3.4 -> [80, 443]"
		}

		var rstOut bytes.Buffer
		cmd := exec.CommandContext(scanCtx, "rustscan", rstArgs...)
		cmd.Stdout = &rstOut
		cmd.Stderr = nil

		if err := cmd.Run(); err != nil && scanCtx.Err() == nil {
			logger.Debugf("rustscan hatası: %v", err)
			color.Yellow("  [!] RustScan başarısız — nmap fallback")
			haveRustScan = false
		} else {
			openPorts = p.parseRustScanGreppable(rstOut.String())
			color.Green("  [✓] RustScan: %d açık web portu bulundu", len(openPorts))
		}
	}

	// ── Adım 2: Nmap -sV ile servis tespiti ───────────────────────────────────
	if haveNmap && len(openPorts) > 0 {
		// Rustscan'ın bulduğu host:port çiftlerine özel nmap taraması
		// Her host için açık portları grupla
		hostPorts := map[string][]string{}
		for _, pi := range openPorts {
			hostPorts[pi.Host] = append(hostPorts[pi.Host], strconv.Itoa(pi.Port))
		}
		var enriched []PortInfo
		for host, ports := range hostPorts {
			nmapCtx, nmapCancel := context.WithTimeout(ctx, 60*time.Second)
			args := []string{
				"-sT",
				"--open",
				"-p", strings.Join(ports, ","),
				"-sV", "--version-intensity", "3",
				"--host-timeout", "55s",
				"--max-retries", "1",
				"-oG", "-",
				host,
			}
			if p.hasRootPrivilege() {
				args[0] = "-sS"
			}
			var out bytes.Buffer
			nmapCmd := exec.CommandContext(nmapCtx, "nmap", args...)
			nmapCmd.Stdout = &out
			nmapCmd.Stderr = nil
			_ = nmapCmd.Run()
			nmapCancel()
			if out.Len() > 0 {
				enriched = append(enriched, p.parseNmapGrepable(out.String())...)
			}
		}
		if len(enriched) > 0 {
			color.Green("  [✓] Nmap -sV: %d port için servis tespiti tamamlandı", len(enriched))
			return enriched
		}
	} else if haveNmap && !haveRustScan {
		// RustScan yok — nmap ile doğrudan tara
		color.Cyan("  [>] Nmap fallback: %d host (max %s)", len(hosts), scanTimeout.Round(time.Second))
		scanType := "-sT"
		if p.hasRootPrivilege() {
			scanType = "-sS"
		}
		nmapArgs := []string{
			scanType, "-T3", "--open",
			"-p", webPorts,
			"-sV", "--version-intensity", "3",
			"--host-timeout", "30s",
			"--max-retries", "1",
			"-oG", "-",
		}
		nmapArgs = append(nmapArgs, hosts...)
		var out bytes.Buffer
		nmapCmd := exec.CommandContext(scanCtx, "nmap", nmapArgs...)
		nmapCmd.Stdout = &out
		nmapCmd.Stderr = nil
		_ = nmapCmd.Run()
		if out.Len() > 0 {
			return p.parseNmapGrepable(out.String())
		}
	}

	return openPorts
}

// parseRustScanGreppable rustscan -g çıktısını parse eder.
// Örnek: "1.2.3.4 -> [80, 443, 8080]"
func (p *Phase3Infrastructure) parseRustScanGreppable(output string) []PortInfo {
	var ports []PortInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// "host -> [port, port, ...]"
		arrow := strings.Index(line, " -> [")
		if arrow == -1 {
			continue
		}
		host := strings.TrimSpace(line[:arrow])
		portsPart := strings.Trim(line[arrow+5:], "]")
		for _, ps := range strings.Split(portsPart, ",") {
			ps = strings.TrimSpace(ps)
			portNum, err := strconv.Atoi(ps)
			if err != nil {
				continue
			}
			if !webPortSet[portNum] {
				continue // web portu değilse atla
			}
			ports = append(ports, PortInfo{
				Host:  host,
				Port:  portNum,
				State: "open",
			})
			if p.cfg.Output.Verbose {
				color.Green("  [+] %s:%d (open)", host, portNum)
			}
		}
	}
	return ports
}

// parseNmapServices — nmapStealthWebScan ile aynı çıktıdan ServiceInfo listesi üretir
func (p *Phase3Infrastructure) parseNmapServices(output string) []ServiceInfo {
	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Host:") {
			continue
		}
		hostPart, domainPart := "", ""
		if idx := strings.Index(line, "Host: "); idx != -1 {
			rest := line[idx+6:]
			parts := strings.Fields(rest)
			if len(parts) >= 1 { hostPart = parts[0] }
			if len(parts) >= 2 { domainPart = strings.Trim(parts[1], "()") }
		}
		display := domainPart
		if display == "" { display = hostPart }
		portsIdx := strings.Index(line, "Ports: ")
		if portsIdx == -1 { continue }
		for _, entry := range strings.Split(line[portsIdx+7:], ", ") {
			fields := strings.Split(strings.TrimSpace(entry), "/")
			if len(fields) < 3 { continue }
			portNum, err := strconv.Atoi(fields[0])
			if err != nil { continue }
			if fields[1] != "open" { continue }
			svc, version := "", ""
			if len(fields) >= 5 { svc = fields[4] }
			if len(fields) >= 7 { version = strings.TrimSpace(fields[6]) }
			if svc == "" && version == "" { continue }
			services = append(services, ServiceInfo{
				Host:    display,
				Port:    portNum,
				Name:    svc,
				Service: svc,
				Version: version,
			})
		}
	}
	return services
}

// parseNmapGrepable nmap -oG çıktısını parse eder
// Örnek satır:
// Host: 93.184.216.34 (example.com)	Ports: 80/open/tcp//http///, 443/open/tcp//https///
func (p *Phase3Infrastructure) parseNmapGrepable(output string) []PortInfo {
var ports []PortInfo

scanner := bufio.NewScanner(strings.NewReader(output))
for scanner.Scan() {
line := scanner.Text()
if !strings.HasPrefix(line, "Host:") {
continue
}

// Host satırını parse et
// "Host: 1.2.3.4 (sub.example.com)"
hostPart := ""
domainPart := ""
if idx := strings.Index(line, "Host: "); idx != -1 {
rest := line[idx+6:]
parts := strings.Fields(rest)
if len(parts) >= 1 {
hostPart = parts[0]
}
if len(parts) >= 2 {
domainPart = strings.Trim(parts[1], "()")
}
}
if hostPart == "" {
continue
}
displayHost := domainPart
if displayHost == "" {
displayHost = hostPart
}

// Ports kısmını parse et
// "Ports: 80/open/tcp//http///, 443/open/tcp//https///"
portsIdx := strings.Index(line, "Ports: ")
if portsIdx == -1 {
continue
}
portsStr := line[portsIdx+7:]
for _, entry := range strings.Split(portsStr, ", ") {
entry = strings.TrimSpace(entry)
if entry == "" {
continue
}
fields := strings.Split(entry, "/")
if len(fields) < 3 {
continue
}
portNum, err := strconv.Atoi(fields[0])
if err != nil {
continue
}
state := fields[1]
proto := fields[2]
svc := ""
if len(fields) >= 5 {
	svc = fields[4]
}
// -sV ile gelen versiyon bilgisi: fields[6] ("Apache httpd 2.4", "nginx 1.22" vb.)
version := ""
if len(fields) >= 7 {
	version = strings.TrimSpace(fields[6])
}
if state == "open" {
pi := PortInfo{
Host:     displayHost,
Port:     portNum,
Protocol: proto,
State:    "open",
Service:  svc,
Version:  version,
}
ports = append(ports, pi)
if p.cfg.Output.Verbose {
if version != "" {
	color.Green("  [+] %s:%d/%s (%s %s)", displayHost, portNum, proto, svc, version)
} else {
	color.Green("  [+] %s:%d/%s (%s)", displayHost, portNum, proto, svc)
}
}
}
}
}
return ports
}

// hasRootPrivilege çalışan işlemin root/sudo yetkisi olup olmadığını kontrol eder
func (p *Phase3Infrastructure) hasRootPrivilege() bool {
cmd := exec.Command("id", "-u")
out, err := cmd.Output()
if err != nil {
return false
}
uid := strings.TrimSpace(string(out))
return uid == "0"
}

// ============================================================================
// Helpers
// ============================================================================

func (p *Phase3Infrastructure) findVHostWordlist() string {
candidates := []string{
"wordlists/dns_bruteforce.txt",
"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
}
for _, c := range candidates {
if _, err := os.Stat(c); err == nil {
return c
}
}
return ""
}

func (p *Phase3Infrastructure) checkInfrastructureToolsAvailability() {
if !p.cfg.Output.Verbose {
return
}
color.Yellow("  [i] Altyapı tarama araçları kontrol ediliyor...")

tools := []struct{ bin, install string }{
{"rustscan", "https://github.com/RustScan/RustScan/releases"},
{"ffuf", "go install github.com/ffuf/ffuf/v2@latest"},
{"nmap", "apt install nmap (opsiyonel, servis tespiti için)"},
}
for _, t := range tools {
if _, err := exec.LookPath(t.bin); err != nil {
color.Yellow("    ! %s kurulu değil  →  %s", t.bin, t.install)
} else {
color.Green("    ✓ %s hazır", t.bin)
}
}
}
