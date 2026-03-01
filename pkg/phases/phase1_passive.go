package phases

import (
	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"
	"bbfucker/pkg/subfinder"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Phase 1: Passive Intelligence & Scope Mapping
// ============================================================================

type Phase1Passive struct {
	cfg *config.Config
}

func NewPhase1Passive() *Phase1Passive {
	return &Phase1Passive{}
}

func (p *Phase1Passive) Name() string {
	return "Phase 1: Passive Intelligence & Scope Mapping"
}

func (p *Phase1Passive) Description() string {
	return "ASN discovery, passive subdomain enumeration (11+ tools), certificate scraping"
}

func (p *Phase1Passive) IsEnabled(cfg *config.Config) bool {
	return cfg.Phase1Passive.Enabled
}

func (p *Phase1Passive) Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error) {
	p.cfg = cfg
	startTime := time.Now()
	log := logger.Default().With("phase", "1-passive", "domain", input.Domain)
	
	color.Cyan("\n[PHASE 1] %s", p.Name())
	color.Cyan("═══════════════════════════════════════════════════════════")
	
	// Check passive intelligence tools availability
	p.checkPassiveToolsAvailability()
	
	output := &PhaseOutput{
		PhaseName:  p.Name(),
		Subdomains: make([]string, 0),
		Statistics: Statistics{
			ToolsUsed: make([]string, 0),
			Extra:     make(map[string]int),
		},
		Extra: make(map[string]interface{}),
	}
	
	// Step 1.1: ASN Discovery (if enabled)
	if cfg.Phase1Passive.ASNDiscovery.Enabled {
		color.Yellow("\n[*] Step 1.1: ASN & Network Mapping")
		asns, ips := p.discoverASN(ctx, input.Domain)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "asnmap", "whois")
		output.Extra["asn_count"] = len(asns)
		output.Extra["ip_ranges"] = ips
		color.Green("[✓] Found %d ASNs and %d IP ranges", len(asns), len(ips))
	}
	
	// Step 1.2: Passive Subdomain Enumeration
	color.Yellow("\n[*] Step 1.2: Passive Subdomain Scraping (11+ sources)")
	
	subdomains := make([]string, 0)
	
	// Subfinder
	if cfg.Phase1Passive.SubdomainEnum.Tools.Subfinder.Enabled {
		color.Cyan("  [>] Running Subfinder...")
		subs := p.runSubfinder(ctx, input.Domain)
		subdomains = append(subdomains, subs...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "subfinder")
		output.Statistics.Extra["subfinder"] = len(subs)
		color.Green("  [✓] Subfinder: %d subdomains", len(subs))
	}
	
	// Amass
	if cfg.Phase1Passive.SubdomainEnum.Tools.Amass.Enabled {
		color.Cyan("  [>] Running Amass (passive)...")
		subs := p.runAmass(ctx, input.Domain)
		subdomains = append(subdomains, subs...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "amass")
		output.Statistics.Extra["amass"] = len(subs)
		color.Green("  [✓] Amass: %d subdomains", len(subs))
	}
	
	// Certificate Transparency (crt.sh)
	if cfg.Phase1Passive.SubdomainEnum.Sources.Crtsh.Enabled {
		color.Cyan("  [>] Scraping crt.sh...")
		subs := p.scrapeCrtsh(ctx, input.Domain)
		subdomains = append(subdomains, subs...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "crtsh")
		output.Statistics.Extra["crtsh"] = len(subs)
		color.Green("  [✓] crt.sh: %d subdomains", len(subs))
	}
	
	// Additional passive sources
	color.Cyan("  [>] Scraping HackerTarget, AlienVault, Wayback...")
	additionalSubs := p.scrapeAdditionalSources(ctx, input.Domain)
	subdomains = append(subdomains, additionalSubs...)
	output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "hackertarget", "alienvault", "wayback")
	output.Statistics.Extra["additional_sources"] = len(additionalSubs)
	color.Green("  [✓] Additional sources: %d subdomains", len(additionalSubs))
	
	// Assetfinder
	if cfg.Phase1Passive.SubdomainEnum.Tools.Assetfinder.Enabled {
		color.Cyan("  [>] Running Assetfinder...")
		subs := p.runAssetfinder(ctx, input.Domain)
		subdomains = append(subdomains, subs...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "assetfinder")
		output.Statistics.Extra["assetfinder"] = len(subs)
		color.Green("  [✓] Assetfinder: %d subdomains", len(subs))
	}

	// Findomain
	if cfg.Phase1Passive.SubdomainEnum.Tools.Findomain.Enabled {
		color.Cyan("  [>] Running Findomain...")
		subs := p.runFindomain(ctx, input.Domain)
		subdomains = append(subdomains, subs...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "findomain")
		output.Statistics.Extra["findomain"] = len(subs)
		color.Green("  [✓] Findomain: %d subdomains", len(subs))
	}

	// Unique and clean
	output.Subdomains = uniqueStrings(subdomains)
	output.Statistics.TotalItems = len(output.Subdomains)
	output.Statistics.Duration = time.Since(startTime).Seconds()

	log.Infof("Phase 1 tamamlandı: %d subdomain, %.2fs", len(output.Subdomains), output.Statistics.Duration)
	color.Green("\n[✓] Phase 1 Complete: %d unique subdomains discovered", len(output.Subdomains))
	color.Cyan("═══════════════════════════════════════════════════════════\n")
	
	return output, nil
}

// ============================================================================
// ASN Discovery Implementation
// ============================================================================

func (p *Phase1Passive) discoverASN(ctx context.Context, domain string) ([]string, []string) {
	var asns []string
	var ipRanges []string

	// asnmap binary wrapper
	if _, err := exec.LookPath("asnmap"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] asnmap kurulu değil, lightweight ASN lookup deneniyor...")
		}
		return p.lightweightASNLookup(ctx, domain)
	}

	// asnmap timeout 20s — daha uzun sürdüğünde OS kill ediyor
	asnCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(asnCtx, "asnmap", "-d", domain, "-silent")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err := cmd.Run(); err != nil {
		if p.cfg.Output.Verbose {
			// SIGKILL / timeout ise kısa mesaj
			if asnCtx.Err() != nil {
				color.Yellow("  [!] asnmap zaman aşımı (20s) — lightweight fallback")
			} else {
				color.Yellow("  [!] asnmap hata verdi — lightweight fallback")
			}
		}
		return p.lightweightASNLookup(ctx, domain)
	}

	// asnmap output parsing
	outStr := out.String()
	if strings.Contains(outStr, "{") {
		// JSON format: {"as_number":"AS13335","as_name":"Cloudflare","as_range":["1.1.1.0/24"]}
		scanner := bufio.NewScanner(strings.NewReader(outStr))
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var entry struct {
				ASNumber string   `json:"as_number"`
				ASName   string   `json:"as_name"`
				ASRange  []string `json:"as_range"`
			}
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
				if entry.ASNumber != "" {
					asns = append(asns, fmt.Sprintf("%s (%s)", entry.ASNumber, entry.ASName))
				}
				ipRanges = append(ipRanges, entry.ASRange...)
			}
		}
	} else {
		// Text format: AS13335, Cloudflare Inc, US
		for _, line := range strings.Split(outStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				asns = append(asns, line)
			}
		}
	}

	// Başarısızsa lightweight'a fallback
	if len(asns) == 0 {
		return p.lightweightASNLookup(ctx, domain)
	}

	return asns, ipRanges
}

// lightweightASNLookup — asnmap alternatifi, daha basit ve hızlı
func (p *Phase1Passive) lightweightASNLookup(ctx context.Context, domain string) ([]string, []string) {
	// Önce IP'yi bul
	resolver := net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		return nil, nil
	}

	var asns []string
	var ipRanges []string

	// Her IP için whois sorgusu (sadece ilk 2 IP)
	for i, ip := range ips {
		if i >= 2 {
			break
		}
		if asn := p.simpleWhoisASN(ctx, ip.String()); asn != "" {
			asns = append(asns, asn)
		}
	}

	return asns, ipRanges
}

// simpleWhoisASN — basit whois tabanlı ASN lookup
func (p *Phase1Passive) simpleWhoisASN(parentCtx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	// whois komutu dene
	cmd := exec.CommandContext(ctx, "whois", ip)
	out, err := cmd.Output()
	if err != nil {
		logger.Debugf("whois ASN sorgusu başarısız: %s - %v", ip, err)
		return ""
	}

	outStr := string(out)
	// ASN pattern'i ara
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "origin") || 
		   strings.Contains(strings.ToLower(line), "originas") ||
		   strings.HasPrefix(strings.ToLower(line), "as") {
			if strings.Contains(line, "AS") {
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}

func (p *Phase1Passive) runAssetfinder(ctx context.Context, domain string) []string {
	if _, err := exec.LookPath("assetfinder"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Assetfinder not installed, skipping...")
		}
		return []string{}
	}

	args := []string{domain}
	if p.cfg.Phase1Passive.SubdomainEnum.Tools.Assetfinder.SubsOnly {
		args = []string{"--subs-only", domain}
	}

	cmd := exec.CommandContext(ctx, "assetfinder", args...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		logger.Debugf("assetfinder çalıştırılamadı: %s - %v", domain, err)
		return []string{}
	}

	var result []string
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasSuffix(line, domain) {
			result = append(result, line)
		}
	}
	return result
}

func (p *Phase1Passive) runFindomain(ctx context.Context, domain string) []string {
	if _, err := exec.LookPath("findomain"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Findomain not installed, skipping...")
		}
		return []string{}
	}

	cmd := exec.CommandContext(ctx, "findomain", "-t", domain, "--quiet")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		logger.Debugf("findomain çalıştırılamadı: %s - %v", domain, err)
		return []string{}
	}

	var result []string
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasSuffix(line, domain) {
			result = append(result, line)
		}
	}
	return result
}

// ============================================================================
// Subdomain Enumeration Tool Implementations
// ============================================================================

func (p *Phase1Passive) runSubfinder(ctx context.Context, domain string) []string {
	// Use existing subfinder module
	scanner := subfinder.NewScanner(p.cfg)
	if !scanner.CheckInstalled() {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Subfinder not installed, skipping...")
		}
		return []string{}
	}
	
	return scanner.FindSubdomains(ctx, domain)
}

func (p *Phase1Passive) runAmass(ctx context.Context, domain string) []string {
	// Check if amass is installed
	if _, err := exec.LookPath("amass"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Amass not installed, skipping...")
		}
		return []string{}
	}
	
	// Run amass enum in passive mode
	cmd := exec.CommandContext(ctx, "amass", "enum", "-passive", "-d", domain, "-silent")
	output, err := cmd.Output()
	if err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Amass error: %v", err)
		}
		return []string{}
	}
	
	subdomains := make([]string, 0)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}
	
	return subdomains
}

func (p *Phase1Passive) scrapeCrtsh(ctx context.Context, domain string) []string {
	crtshURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", url.QueryEscape(domain))
	client := &http.Client{Timeout: 30 * time.Second}
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crtshURL, nil)
	if err != nil {
		logger.Debugf("crt.sh request oluşturulamadı: %v", err)
		return []string{}
	}
	resp, err := client.Do(req)
	if err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] crt.sh error: %v", err)
		}
		return []string{}
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] crt.sh body okuma hatası: %v", err)
		}
		return []string{}
	}
	
	var certs []struct {
		NameValue string `json:"name_value"`
	}
	
	if err := json.Unmarshal(body, &certs); err != nil {
		logger.Debugf("crt.sh JSON parse hatası: %v", err)
		return []string{}
	}
	
	subdomains := make(map[string]bool)
	for _, cert := range certs {
		for _, name := range strings.Split(cert.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if strings.HasSuffix(name, domain) && name != "" {
				subdomains[name] = true
			}
		}
	}
	
	result := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		result = append(result, sub)
	}

	return result
}

func (p *Phase1Passive) scrapeAdditionalSources(ctx context.Context, domain string) []string {
	allSubdomains := make(map[string]bool)
	client := &http.Client{Timeout: 30 * time.Second}

	// helper to do context-aware GET
	ctxGet := func(url string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		return client.Do(req)
	}
	
	// HackerTarget
	if resp, err := ctxGet(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))); err == nil {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if readErr == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if strings.Contains(line, ",") {
					parts := strings.Split(line, ",")
					if sub := strings.TrimSpace(parts[0]); strings.HasSuffix(sub, domain) {
						allSubdomains[sub] = true
					}
				}
			}
		}
	}
	
	// AlienVault
	if resp, err := ctxGet(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))); err == nil {
		var data struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		if decodeErr == nil {
			for _, entry := range data.PassiveDNS {
				if hostname := strings.TrimSpace(entry.Hostname); strings.HasSuffix(hostname, domain) {
					allSubdomains[hostname] = true
				}
			}
		}
	}
	
	// Wayback Machine
	if resp, err := ctxGet(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", url.QueryEscape(domain))); err == nil {
		var entries [][]string
		decodeErr := json.NewDecoder(resp.Body).Decode(&entries)
		resp.Body.Close()
		if decodeErr == nil {
			for i, entry := range entries {
				if i == 0 || len(entry) == 0 {
					continue
				}
				fullURL := entry[0]
				if strings.Contains(fullURL, "://") {
					parts := strings.Split(fullURL, "://")
					if len(parts) > 1 {
						hostPath := strings.Split(parts[1], "/")
						hostname := strings.Split(hostPath[0], ":")[0]
						if strings.HasSuffix(hostname, domain) {
							allSubdomains[hostname] = true
						}
					}
				}
			}
		}
	}
	
	result := make([]string, 0, len(allSubdomains))
	for sub := range allSubdomains {
		result = append(result, sub)
	}
	
	return result
}

// checkPassiveToolsAvailability verifies if external tools are available and provides helpful feedback
func (p *Phase1Passive) checkPassiveToolsAvailability() {
	if !p.cfg.Output.Verbose {
		return
	}
	type tool struct{ bin, install string }
	tools := []tool{
		{"subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"assetfinder", "go install github.com/tomnomnom/assetfinder@latest"},
		{"asnmap", "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"},
		{"amass", "go install github.com/owasp-amass/amass/v4/...@latest"},
		{"findomain", "https://github.com/Findomain/Findomain/releases"},
	}
	color.Yellow("  [i] Pasif tarama araçları kontrol ediliyor...")
	for _, t := range tools {
		if _, err := exec.LookPath(t.bin); err != nil {
			color.Yellow("    ! %s kurulu değil  →  %s", t.bin, t.install)
		} else {
			color.Green("    ✓ %s hazır", t.bin)
		}
	}
}
