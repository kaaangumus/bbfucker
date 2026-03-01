package phases

import (
	"bbfucker/pkg/config"
	"bbfucker/pkg/gau"
	"bbfucker/pkg/katana"
	"bbfucker/pkg/logger"
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Phase 5: Deep Content & JavaScript Analysis
// ============================================================================

type Phase5ContentAnalysis struct {
	cfg *config.Config
}

func NewPhase5ContentAnalysis() *Phase5ContentAnalysis {
	return &Phase5ContentAnalysis{}
}

func (p *Phase5ContentAnalysis) Name() string {
	return "Phase 5: Deep Content & JavaScript Analysis"
}

func (p *Phase5ContentAnalysis) Description() string {
	return "Waymore archive mining, Katana crawling, JS endpoint extraction, secret scanning"
}

func (p *Phase5ContentAnalysis) IsEnabled(cfg *config.Config) bool {
	return cfg.Phase5ContentAnalysis.Enabled
}

func (p *Phase5ContentAnalysis) Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error) {
	p.cfg = cfg
	startTime := time.Now()
	log := logger.Default().With("phase", "5-content", "domain", input.Domain)
	
	color.Cyan("\n[PHASE 5] %s", p.Name())
	color.Cyan("═══════════════════════════════════════════════════════════")
	
	output := &PhaseOutput{
		PhaseName:  p.Name(),
		URLs:       make([]string, 0),
		JSFiles:    make([]string, 0),
		Endpoints:  make([]string, 0),
		Findings:   make([]Finding, 0),
		Statistics: Statistics{
			ToolsUsed: make([]string, 0),
			Extra:     make(map[string]int),
		},
		Extra: make(map[string]interface{}),
	}
	
	// Check content analysis tools availability
	p.checkContentToolsAvailability()
	
	// Step 5.1: URL Archive Extraction
	if cfg.Phase5ContentAnalysis.URLExtraction.Enabled {
		color.Yellow("\n[*] Step 5.1: Archive URL Extraction")
		
		// Waymore
		if cfg.Phase5ContentAnalysis.URLExtraction.Waymore.Enabled {
			color.Cyan("  [>] Running Waymore...")
			urls := p.extractWaymore(ctx, input.Domain)
			output.URLs = append(output.URLs, urls...)
			output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "waymore")
			output.Statistics.Extra["waymore"] = len(urls)
			color.Green("  [✓] Waymore: %d URLs", len(urls))
		}
		
		// Gau
		if cfg.Phase5ContentAnalysis.URLExtraction.Gau.Enabled {
			color.Cyan("  [>] Running Gau...")
			urls := p.extractGau(ctx, input.Domain)
			output.URLs = append(output.URLs, urls...)
			output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "gau")
			output.Statistics.Extra["gau"] = len(urls)
			color.Green("  [✓] Gau: %d URLs", len(urls))
		}
		
		// Katana
		if cfg.Phase5ContentAnalysis.URLExtraction.Katana.Enabled {
			color.Cyan("  [>] Running Katana (JS-aware)...")
			urls := p.crawlKatana(ctx, input.LiveHosts)
			output.URLs = append(output.URLs, urls...)
			output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "katana")
			output.Statistics.Extra["katana"] = len(urls)
			color.Green("  [✓] Katana: %d URLs", len(urls))
		}
	}
	
	// Step 5.2: JavaScript Discovery
	if cfg.Phase5ContentAnalysis.JavaScript.Enabled {
		color.Yellow("\n[*] Step 5.2: JavaScript File Discovery")
		jsFiles := p.discoverJSFiles(ctx, output.URLs)
		output.JSFiles = jsFiles
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "getjs")
		output.Statistics.Extra["js_files"] = len(jsFiles)
		color.Green("[✓] Found %d JavaScript files", len(jsFiles))
		
		// Step 5.3: Extract Endpoints from JS
		if cfg.Phase5ContentAnalysis.JavaScript.EndpointExtraction.Enabled {
			color.Yellow("\n[*] Step 5.3: Extracting Endpoints from JS")
			endpoints := p.extractJSEndpoints(ctx, jsFiles)
			output.Endpoints = endpoints
			output.Statistics.Extra["endpoints"] = len(endpoints)
			color.Green("[✓] Extracted %d endpoints", len(endpoints))
		}
		
		// Step 5.4: Secret Scanning
		if cfg.Phase5ContentAnalysis.JavaScript.SecretScanning.Enabled {
			color.Yellow("\n[*] Step 5.4: Scanning for Secrets/API Keys")
			secrets := p.scanSecrets(ctx, jsFiles)
			for _, secret := range secrets {
				output.Findings = append(output.Findings, Finding{
					Type:        "secret_exposure",
					Severity:    "high",
					Title:       "Potential API Key/Secret Found",
					Description: secret,
				})
			}
			output.Statistics.Extra["secrets"] = len(secrets)
			color.Green("[✓] Found %d potential secrets", len(secrets))
		}
	}
	
	// Step 5.5: Sensitive File Extraction
	if cfg.Phase5ContentAnalysis.SensitiveFiles.Enabled {
		color.Yellow("\n[*] Step 5.5: Extracting Sensitive Files")
		sensitiveFiles := p.extractSensitiveFiles(ctx, output.URLs)
		output.Statistics.Extra["sensitive_files"] = len(sensitiveFiles)
		// SensitiveFile struct'larını doldur (veri kaybını önle)
		for _, sf := range sensitiveFiles {
			sfType := classifySensitiveFile(sf)
			output.SensitiveFiles = append(output.SensitiveFiles, SensitiveFile{
				URL:  sf,
				Type: sfType,
			})
		}
		output.Extra["sensitive_files"] = sensitiveFiles
		color.Green("[✓] Found %d sensitive files (.pdf, .sql, .bak, .zip...)", len(sensitiveFiles))
	}
	
	rawURLCount := len(output.URLs)
	output.URLs = filterNoiseURLs(output.URLs)
	output.URLs = uniqueStrings(output.URLs)
	if rawURLCount > len(output.URLs) && p.cfg.Output.Verbose {
		color.Yellow("  [~] %d gürültülü URL çıkarıldı (feeds, static, label...) → %d temiz URL kaldı",
			rawURLCount-len(output.URLs), len(output.URLs))
	}
	output.Statistics.TotalItems = len(output.URLs) + len(output.JSFiles) + len(output.Endpoints)
	output.Statistics.Duration = time.Since(startTime).Seconds()

	log.Infof("Phase 5 tamamlandı: %d URL, %d JS, %d endpoint, %.2fs", len(output.URLs), len(output.JSFiles), len(output.Endpoints), output.Statistics.Duration)
	color.Green("\n[✓] Phase 5 Complete: %d URLs, %d JS files, %d endpoints", len(output.URLs), len(output.JSFiles), len(output.Endpoints))
	color.Cyan("═══════════════════════════════════════════════════════════\n")
	
	return output, nil
}

// ============================================================================
// Content Analysis Implementations
// ============================================================================

// filterNoiseURLs — gau/waymore/katana çıktısındaki gürültülü URL'leri temizler.
// Kaldırılan kategoriler:
//   - Blogger/RSS feed URL'leri  (/feeds/)
//   - CMS kategori/etiket URL'leri (/search/label/, /tag/, /category/)
//   - Statik medya dosyaları (.mp4, .png, .jpg, .gif, .ico, .svg, .woff vb.)
//   - Google Analytics / CDN gürültüsü (google-analytics.com, fonts.googleapis, vb.)
func filterNoiseURLs(urls []string) []string {
	// Path prefix'leri (gau'dan gelen CMS/platform URL'leri)
	noisePaths := []string{
		"/feeds/",
		"/search/label/",
		"/search/label",
		"/tag/",
		"/category/",
		"/wp-json/",
		"/xmlrpc.php",
		"/trackback/",
		"/comments/feed",
	}
	// Statik dosya uzantıları
	staticExts := map[string]bool{
		".mp4": true, ".webm": true, ".ogv": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".svg": true, ".webp": true, ".bmp": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".otf": true,
		".mp3": true, ".ogg": true, ".wav": true,
	}
	// Güvenlik açığı tarama için değersiz host pattern'ları
	noiseHosts := []string{
		"google-analytics.com",
		"analytics.google.com",
		"fonts.googleapis.com",
		"fonts.gstatic.com",
		"staticxx.facebook.com",
		"connect.facebook.net",
		"platform.twitter.com",
		"ajax.googleapis.com",
		"cdn.jsdelivr.net",
		"cdnjs.cloudflare.com",
		"unpkg.com",
	}

	result := make([]string, 0, len(urls))
outer:
	for _, rawURL := range urls {
		// Gürültülü host kontrolü
		for _, nh := range noiseHosts {
			if strings.Contains(rawURL, nh) {
				continue outer
			}
		}
		// Path prefix kontrolü
		pathPart := rawURL
		if idx := strings.Index(rawURL, "//"); idx != -1 {
			pathPart = rawURL[idx+2:]
			if slashIdx := strings.Index(pathPart, "/"); slashIdx != -1 {
				pathPart = pathPart[slashIdx:]
			}
		}
		for _, np := range noisePaths {
			if strings.HasPrefix(pathPart, np) {
				continue outer
			}
		}
		// Statik uzantı kontrolü
		purePath := strings.SplitN(rawURL, "?", 2)[0]
		purePath = strings.SplitN(purePath, "#", 2)[0]
		dot := strings.LastIndex(purePath, ".")
		if dot != -1 {
			ext := strings.ToLower(purePath[dot:])
			if staticExts[ext] {
				continue
			}
		}
		result = append(result, rawURL)
	}
	return result
}

func (p *Phase5ContentAnalysis) extractWaymore(ctx context.Context, domain string) []string {
	// Check if waymore is installed
	if _, err := exec.LookPath("waymore"); err != nil {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Waymore not installed, skipping...")
		}
		return []string{}
	}

	cmd := exec.CommandContext(ctx, "waymore", "-i", domain, "-mode", "U", "-p", "rl,og,vt,wb")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		logger.Debugf("waymore çalıştırılamadı: %s - %v", domain, err)
		return []string{}
	}

	var urls []string
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}
	return urls
}

func (p *Phase5ContentAnalysis) extractGau(ctx context.Context, domain string) []string {
	// Use existing gau module
	gauCrawler := gau.NewCrawler(p.cfg)
	if !gauCrawler.CheckInstalled() {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Gau not installed, skipping...")
		}
		return []string{}
	}
	
	return gauCrawler.GetURLs(ctx, domain)
}

func (p *Phase5ContentAnalysis) crawlKatana(ctx context.Context, hosts []LiveHost) []string {
	// Use existing katana module
	katanaCrawler := katana.NewCrawler(p.cfg)
	if !katanaCrawler.CheckInstalled() {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Katana not installed, skipping...")
		}
		return []string{}
	}
	
	// Extract URLs from LiveHosts
	targets := make([]string, len(hosts))
	for i, host := range hosts {
		targets[i] = host.URL
	}
	
	return katanaCrawler.CrawlMultiple(ctx, targets)
}

func (p *Phase5ContentAnalysis) discoverJSFiles(ctx context.Context, urls []string) []string {
	// Filter URLs ending in .js from collected URLs
	jsFiles := make([]string, 0)
	client := &http.Client{Timeout: 10 * time.Second}
	
	for _, u := range urls {
		if strings.HasSuffix(strings.ToLower(strings.Split(u, "?")[0]), ".js") {
			// Verify JS file exists (HTTP 200)
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
			if err != nil {
				continue
			}
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					jsFiles = append(jsFiles, u)
				}
			}
		}
	}
	
	return jsFiles
}

func (p *Phase5ContentAnalysis) extractJSEndpoints(ctx context.Context, jsFiles []string) []string {
	// Fetch JS content and extract endpoints using regex patterns
	endpoints := make(map[string]bool)
	client := &http.Client{Timeout: 15 * time.Second}
	
	// Endpoint extraction patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:url|endpoint|api|href|action)\s*[:=]\s*[\"\']([/][\w\-/\.\?\=\&]+)[\"\']`),
		regexp.MustCompile(`(?i)[\"\'](\/api\/[\w\-/\.\?\=\&]*)[\"\'\s]`),
		regexp.MustCompile(`(?i)[\"\'](\/v[0-9]+\/[\w\-/\.\?\=\&]*)[\"\'\s]`),
		regexp.MustCompile(`(?i)[\"\'](\/[\w]+\/[\w\-/]{3,})[\"\']`),
	}
	
	for _, jsURL := range jsFiles {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
		if err != nil {
			logger.Debugf("JS endpoint request hatası: %s - %v", jsURL, err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Debugf("JS dosyası indirilemedi: %s - %v", jsURL, err)
			continue
		}
		// Döngü içinde defer kullanma — body'yi hemen kapat
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			logger.Debugf("JS body okuma hatası: %s - %v", jsURL, err)
			continue
		}
		content := string(bodyBytes)
		
		for _, pattern := range patterns {
			matches := pattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 && match[1] != "" {
					endpoints[match[1]] = true
				}
			}
		}
	}
	
	result := make([]string, 0, len(endpoints))
	for ep := range endpoints {
		result = append(result, ep)
	}
	
	return result
}

func (p *Phase5ContentAnalysis) scanSecrets(ctx context.Context, jsFiles []string) []string {
	// Scan JS files for sensitive patterns
	foundSecrets := make([]string, 0)
	client := &http.Client{Timeout: 15 * time.Second}
	
	// Secret detection patterns
	secretPatterns := map[string]*regexp.Regexp{
		"api_key":      regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[\"\']([\w\-]{16,})[\"\']`),
		"access_token": regexp.MustCompile(`(?i)(?:access[_-]?token)\s*[=:]\s*[\"\']([\w\-\.]{16,})[\"\']`),
		"secret_key":   regexp.MustCompile(`(?i)(?:secret[_-]?key|secret)\s*[=:]\s*[\"\']([\w\-]{16,})[\"\']`),
		"aws_access":   regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		"bearer":       regexp.MustCompile(`(?i)bearer\s+([\w\-\.]{16,})`),
		"password":     regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"\']([^\"\']{8,})[\"\']`),
		"database_url": regexp.MustCompile(`(?i)((?:mysql|postgres|mongodb|redis):\/\/[\w:\-@\/]+)`),
	}
	
	for _, jsURL := range jsFiles {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
		if err != nil {
			logger.Debugf("secret scan request hatası: %s - %v", jsURL, err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Debugf("secret scan indirme hatası: %s - %v", jsURL, err)
			continue
		}
		// Döngü içinde defer kullanma — body'yi hemen kapat
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			logger.Debugf("secret scan body okuma hatası: %s - %v", jsURL, err)
			continue
		}
		content := string(bodyBytes)
		
		for secretType, pattern := range secretPatterns {
			matches := pattern.FindAllStringSubmatch(content, 3)
			for _, match := range matches {
				if len(match) > 1 {
					foundSecrets = append(foundSecrets,
						secretType+": "+match[1]+" (in "+jsURL+")")
				}
			}
		}
	}
	
	return foundSecrets
}

func (p *Phase5ContentAnalysis) extractSensitiveFiles(ctx context.Context, urls []string) []string {
	// Filter URLs that match sensitive file extensions
	sensitiveExts := []string{
		".xls", ".xlsx", ".xml", ".json",
		".pdf", ".sql", ".doc", ".docx",
		".zip", ".bak", ".config", ".yaml",
		".env", ".log", ".db", ".sqlite",
		".tar.gz", ".tar", ".7z", ".pem",
		".key", ".p12", ".pfx", ".cer",
		".htpasswd", ".htaccess", ".npmrc",
	}
	
	sensitiveFiles := make([]string, 0)
	for _, url := range urls {
		lowURL := strings.ToLower(strings.Split(url, "?")[0])
		for _, ext := range sensitiveExts {
			if strings.HasSuffix(lowURL, ext) {
				sensitiveFiles = append(sensitiveFiles, url)
				break
			}
		}
	}
	
	return sensitiveFiles
}

// classifySensitiveFile — URL uzantısına göre dosya türünü belirler
func classifySensitiveFile(url string) string {
	lowURL := strings.ToLower(strings.Split(url, "?")[0])
	typeMap := map[string]string{
		".sql": "database", ".db": "database", ".sqlite": "database",
		".bak": "backup", ".tar.gz": "backup", ".tar": "backup", ".7z": "backup", ".zip": "backup",
		".env": "config", ".config": "config", ".yaml": "config", ".yml": "config",
		".htpasswd": "config", ".htaccess": "config", ".npmrc": "config",
		".log": "log",
		".pdf": "document", ".doc": "document", ".docx": "document",
		".xls": "spreadsheet", ".xlsx": "spreadsheet",
		".xml": "data", ".json": "data",
		".pem": "certificate", ".key": "certificate", ".p12": "certificate",
		".pfx": "certificate", ".cer": "certificate",
	}
	for ext, t := range typeMap {
		if strings.HasSuffix(lowURL, ext) {
			return t
		}
	}
	return "unknown"
}

// checkContentToolsAvailability verifies if external tools are available and provides helpful feedback
func (p *Phase5ContentAnalysis) checkContentToolsAvailability() {
	if !p.cfg.Output.Verbose {
		return
	}
	type tool struct{ bin, install string }
	tools := []tool{
		{"waymore", "pip install waymore"},
		{"gau", "go install github.com/lc/gau/v2/cmd/gau@latest"},
		{"katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
	}
	color.Yellow("  [i] İçerik analiz araçları kontrol ediliyor...")
	for _, t := range tools {
		if _, err := exec.LookPath(t.bin); err != nil {
			color.Yellow("    ! %s kurulu değil  →  %s", t.bin, t.install)
		} else {
			color.Green("    ✓ %s hazır", t.bin)
		}
	}
}
