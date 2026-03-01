package phases

import (
	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Phase 2: DNS Resolution & Brute-forcing
// ============================================================================

type Phase2DNS struct {
	cfg *config.Config
}

func NewPhase2DNS() *Phase2DNS {
	return &Phase2DNS{}
}

func (p *Phase2DNS) Name() string {
	return "Phase 2: DNS Resolution & Brute-forcing"
}

func (p *Phase2DNS) Description() string {
	return "Puredns resolution, DNS brute-force, subdomain permutations"
}

func (p *Phase2DNS) IsEnabled(cfg *config.Config) bool {
	return cfg.Phase2DNS.Enabled
}

func (p *Phase2DNS) Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error) {
	p.cfg = cfg
	startTime := time.Now()
	log := logger.Default().With("phase", "2-dns", "domain", input.Domain)
	
	color.Cyan("\n[PHASE 2] %s", p.Name())
	color.Cyan("═══════════════════════════════════════════════════════════")
	
	// Check DNS resolution tools availability
	p.checkDNSToolsAvailability()
	
	output := &PhaseOutput{
		PhaseName:       p.Name(),
		ResolvedDomains: make([]string, 0),
		Statistics: Statistics{
			ToolsUsed: make([]string, 0),
			Extra:     make(map[string]int),
		},
		Extra: make(map[string]interface{}),
	}
	
	// Step 2.1: Resolve with Puredns
	if cfg.Phase2DNS.Resolution.Enabled {
		color.Yellow("\n[*] Step 2.1: DNS Resolution (Puredns)")
		resolved := p.resolveDomains(ctx, input.Subdomains)
		output.ResolvedDomains = append(output.ResolvedDomains, resolved...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "puredns")
		output.Statistics.Extra["resolved"] = len(resolved)
		color.Green("[✓] Resolved %d/%d subdomains", len(resolved), len(input.Subdomains))
	}

	// Step 2.2: DNS Brute-force (wordlist tabanlı yeni subdomain keşfi)
	if cfg.Phase2DNS.Bruteforce.Enabled {
		color.Yellow("\n[*] Step 2.2: DNS Brute-force")
		bruted := p.bruteForceDNS(ctx, input.Domain)
		if len(bruted) > 0 {
			output.ResolvedDomains = append(output.ResolvedDomains, bruted...)
			output.Subdomains = append(output.Subdomains, bruted...)
			output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "puredns-bruteforce")
			output.Statistics.Extra["bruteforce"] = len(bruted)
			color.Green("[\u2713] Brute-force: %d yeni subdomain", len(bruted))
		} else {
			color.Yellow("  [i] Brute-force: yeni subdomain bulunamad\u0131 (wordlist eksik veya t\u00fcm domainler zaten biliniyor)")
		}
	}

	// Unique and final
	output.ResolvedDomains = uniqueStrings(output.ResolvedDomains)
	output.Statistics.TotalItems = len(output.ResolvedDomains)
	output.Statistics.Duration = time.Since(startTime).Seconds()

	log.Infof("Phase 2 tamamlandı: %d resolved domain, %.2fs", len(output.ResolvedDomains), output.Statistics.Duration)
	color.Green("\n[✓] Phase 2 Complete: %d resolved & validated domains", len(output.ResolvedDomains))
	color.Cyan("═══════════════════════════════════════════════════════════\n")
	
	return output, nil
}

// ============================================================================
// DNS Resolution & Brute-force Implementations
// ============================================================================

// resolveDomains - Puredns ile subdomain listesini DNS üzerinden validate eder
func (p *Phase2DNS) resolveDomains(ctx context.Context, subdomains []string) []string {
	if len(subdomains) == 0 {
		return []string{}
	}

	// puredns binary kontrolü
	if _, err := exec.LookPath("puredns"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("[!] puredns kurulu değil — dnsx fallback")
		}
		return p.resolveWithDNSx(ctx, subdomains)
	}

	// Geçici input dosyası oluştur
	tmpInput, err := os.CreateTemp("", "bbfucker_subs_*.txt")
	if err != nil {
		color.Yellow("[!] Temp dosyası oluşturulamadı: %v", err)
		return subdomains
	}
	defer os.Remove(tmpInput.Name())

	for _, s := range subdomains {
		fmt.Fprintln(tmpInput, s)
	}
	tmpInput.Close()

	// Resolvers dosyasını bul
	resolversFile := p.findResolversFile()

	// puredns resolve komutu
	args := []string{"resolve", tmpInput.Name()}
	if resolversFile != "" {
		args = append(args, "-r", resolversFile)
	}
	// --wildcard-batch 500k: 1M çok agresif, memory spike yapabilir
	// --wildcard-tests 3: 5 yerine 3 — daha az DNS flood
	args = append(args, "--wildcard-tests", "3", "--wildcard-batch", "500000")

	cmd := exec.CommandContext(ctx, "puredns", args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// puredns çalıştırılamadı (resolvers.txt eksik veya başka hata) — dnsx ile devam
		if p.cfg.Output.Verbose {
			// resolvers.txt yoksa net mesaj ver
			if resolversFile == "" {
				color.Yellow("[!] puredns: resolvers.txt bulunamadı — dnsx fallback")
				color.Yellow("    Resolver listesi için: wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt")
			} else {
				color.Yellow("[!] puredns çalışırken hata oluştu — dnsx fallback")
			}
		}
		return p.resolveWithDNSx(ctx, subdomains)
	}

	var resolved []string
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	progressStep := 100
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			resolved = append(resolved, line)
			if len(resolved)%progressStep == 0 {
				color.Cyan("[DNS] %d/%d subdomain çözüldü...", len(resolved), len(subdomains))
			}
		}
	}

	if len(resolved) == 0 {
		color.Yellow("  [!] puredns sonuç döndürmedi — orijinal subdomain listesi kullanılıyor (resolve doğrulanmamış!)")
		return subdomains
	}
	return resolved
}

// resolveWithDNSx - puredns yoksa dnsx ile resolve fallback
func (p *Phase2DNS) resolveWithDNSx(ctx context.Context, subdomains []string) []string {
	input := strings.Join(subdomains, "\n")
	// -resp kullanma: -resp-only sadece IP döndürür, hostname kaybeder
	// -silent -a ile resolve olan domain'ler stdout'a yazılır
	cmd := exec.CommandContext(ctx, "dnsx", "-silent", "-a")
	cmd.Stdin = strings.NewReader(input)

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		color.Yellow("[!] DNSx de bulunamadı, subdomain'ler olduğu gibi kullanılıyor")
		return subdomains
	}

	var resolved []string
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// dnsx -a çıktısı: "sub.example.com [1.2.3.4]" veya sadece "sub.example.com"
		// Köşeli parantez varsa hostname kısmını al
		if idx := strings.Index(line, " ["); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			resolved = append(resolved, line)
		}
	}
	if len(resolved) == 0 {
		return subdomains
	}
	return resolved
}

// bruteForceDNS - Puredns ile wordlist tabanlı brute-force
func (p *Phase2DNS) bruteForceDNS(ctx context.Context, domain string) []string {
	wordlist := p.findWordlist()
	if wordlist == "" {
		color.Yellow("[!] DNS brute-force wordlist bulunamadı, atlanıyor")
		return []string{}
	}

	// puredns binary kontrolü
	if _, err := exec.LookPath("puredns"); err != nil {
		return p.bruteForceDNSx(ctx, domain, wordlist)
	}

	resolversFile := p.findResolversFile()
	if resolversFile == "" {
		if p.cfg.Output.Verbose {
			color.Yellow("[!] puredns bruteforce: resolvers.txt yok — dnsx fallback")
		}
		return p.bruteForceDNSx(ctx, domain, wordlist)
	}

	args := []string{"bruteforce", domain, wordlist, "-r", resolversFile}
	args = append(args, "--wildcard-tests", "3", "--wildcard-batch", "500000")

	cmd := exec.CommandContext(ctx, "puredns", args...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		// Fallback: dnsx ile brute-force
		return p.bruteForceDNSx(ctx, domain, wordlist)
	}

	var results []string
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasSuffix(line, domain) {
			results = append(results, line)
		}
	}
	return results
}

// bruteForceDNSx - puredns yoksa dnsx ile brute-force fallback
func (p *Phase2DNS) bruteForceDNSx(ctx context.Context, domain string, wordlist string) []string {
	// Wordlist'ten subdomain'leri oluştur
	f, err := os.Open(wordlist)
	if err != nil {
		logger.Warnf("DNS brute-force wordlist açılamadı: %s - %v", wordlist, err)
		return []string{}
	}
	defer f.Close()

	var candidates []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			candidates = append(candidates, word+"."+domain)
		}
	}

	if len(candidates) == 0 {
		return []string{}
	}

	// dnsx ile doğrula — -resp-only KULLANMA (IP döndürür, hostname kaybeder)
	input := strings.Join(candidates, "\n")
	cmd := exec.CommandContext(ctx, "dnsx", "-silent", "-a")
	cmd.Stdin = strings.NewReader(input)

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		logger.Warnf("dnsx brute-force başarısız: %s - %v", domain, err)
		return []string{}
	}

	var results []string
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// "sub.example.com [1.2.3.4]" → "sub.example.com"
		if idx := strings.Index(line, " ["); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			results = append(results, line)
		}
	}
	return results
}
// ...existing code...

// ============================================================================
// Helpers
// ============================================================================

// findResolversFile - Resolvers dosyasını config'den veya bilinen lokasyonlardan bulur
func (p *Phase2DNS) findResolversFile() string {
	// Config'den kontrol et
	if p.cfg.Phase2DNS.Resolution.ResolverFile != "" {
		if _, err := os.Stat(p.cfg.Phase2DNS.Resolution.ResolverFile); err == nil {
			return p.cfg.Phase2DNS.Resolution.ResolverFile
		}
	}

	// Bilinen lokasyonlar
	candidates := []string{
		"wordlists/resolvers.txt",
		"/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
		filepath.Join(os.Getenv("HOME"), ".config/bbfucker/resolvers.txt"),
		"/opt/resolvers.txt",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// checkDNSToolsAvailability DNS araçlarını kontrol eder
func (p *Phase2DNS) checkDNSToolsAvailability() {
	if !p.cfg.Output.Verbose {
		return
	}
	type tool struct{ bin, install string }
	tools := []tool{
		{"puredns", "go install github.com/d3mondev/puredns/v2@latest"},
		{"dnsx", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	}
	color.Yellow("  [i] DNS araçları kontrol ediliyor...")
	for _, t := range tools {
		if _, err := exec.LookPath(t.bin); err != nil {
			color.Yellow("    ! %s kurulu değil  →  %s", t.bin, t.install)
		} else {
			color.Green("    ✓ %s hazır", t.bin)
		}
	}
}
// findWordlist - DNS brute-force wordlist'ini bulur
func (p *Phase2DNS) findWordlist() string {
	// Config'den kontrol et
	if p.cfg.Phase2DNS.Bruteforce.Wordlist != "" {
		if _, err := os.Stat(p.cfg.Phase2DNS.Bruteforce.Wordlist); err == nil {
			return p.cfg.Phase2DNS.Bruteforce.Wordlist
		}
	}

	// Bilinen lokasyonlar
	candidates := []string{
		"wordlists/dns_bruteforce.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
		"/opt/wordlists/subdomain.txt",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
