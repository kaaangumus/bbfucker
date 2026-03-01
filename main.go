package main

// ============================================================================
// BB FUCKER - 6-Phase Professional Bug Bounty Automation
// Platform: Linux (Kali/Ubuntu/Debian) - Optimized for Linux!
// ============================================================================
// 
// PLATFORM REQUIREMENTS:
//   - Linux distro with apt-get (Kali/Ubuntu/Debian recommended)
//   - External tools: wafw00f, wpscan, whatweb, sqlmap, nmap (Linux-native)
//   - Wordlists: /usr/share/seclists (Linux standard path)
//
// CROSS-PLATFORM NOTES:
//   - Core Go code works on Windows/macOS
//   - External tool integrations require Linux or manual setup
//   - For Windows users: Use WSL (Windows Subsystem for Linux)
//
// ============================================================================

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"
	"bbfucker/pkg/notification"
	"bbfucker/pkg/phases"
	"bbfucker/pkg/reporter"
	"bbfucker/pkg/screenshot"

	"github.com/fatih/color"
)

var (
	domain     = flag.String("d", "", "Hedef domain (zorunlu)")
	configFile = flag.String("config", "config.yaml", "Konfigürasyon dosyası")
	threads    = flag.Int("threads", 0, "Worker sayısı (0=config'den al)")
	verbose    = flag.Bool("v", false, "Detaylı çıktı")
	deepScan   = flag.Bool("deep", false, "Derin tarama modu")
	phaseOnly  = flag.String("phase", "", "Sadece belirli phase'i çalıştır (1-6) [eski]")
	scanMode   = flag.String("mode", "full", "Tarama modu: full | recon | web | p3 | 1,2,3,4 | 1-4")
)

func main() {
	flag.Parse()

	if *domain == "" {
		printBanner()
		flag.Usage()
		os.Exit(1)
	}

	// Domain doğrulama — komut enjeksiyonu ve path traversal önleme
	if err := validateDomain(*domain); err != nil {
		log.Fatalf("Geçersiz domain: %v", err)
	}

	// Config yükle — CWD bulunamadıysa /opt/bbfucker/ fallback
	if *configFile == "config.yaml" {
		if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
			*configFile = "/opt/bbfucker/config.yaml"
		}
	}
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Config yüklenemedi: %v", err)
	}

	// Thread override
	if *threads > 0 {
		cfg.Settings.MaxWorkers = *threads
	}
	if *verbose {
		cfg.Output.Verbose = true
	}
	if *deepScan {
		cfg.Settings.DeepScan = true
	}

	printBanner()
	fmt.Printf("%s\n", color.YellowString("[*] Hedef Domain: %s", *domain))
	fmt.Printf("%s\n", color.YellowString("[*] Workers: %d (Go Goroutines - ÇOK HIZLI!)", cfg.Settings.MaxWorkers))
	fmt.Printf("%s\n\n", color.YellowString("[*] Tarama Zamanı: %s", time.Now().Format("2006-01-02 15:04:05")))

	// Output dizini oluştur
	timestamp := time.Now().Format("20060102_150405")
	outputDir := filepath.Join("results", *domain, timestamp)
	// Path traversal koruması — output dizini results/ altında kalmalı
	cleanedDir := filepath.Clean(outputDir)
	if !strings.HasPrefix(cleanedDir, filepath.Clean("results")) {
		log.Fatalf("Güvenlik hatası: output dizini 'results/' dışına çıkıyor: %s", cleanedDir)
	}
	if err := os.MkdirAll(cleanedDir, 0755); err != nil {
		log.Fatalf("Output dizini oluşturulamadı: %v", err)
	}

	// Logger başlat — verbose/debug’a göre seviye ayarla, dosyaya da yaz
	logLevel := logger.LevelFromConfig(cfg.Output.Verbose, cfg.Output.Debug)
	if err := logger.Init(logger.Options{
		Level:   logLevel,
		LogFile: filepath.Join(outputDir, "scan.log"),
		Console: true,
	}); err != nil {
		log.Fatalf("Logger başlatılamadı: %v", err)
	}
	defer logger.Close()

	logger.Info("BBFucker başlatıldı",
		"domain", *domain,
		"workers", fmt.Sprintf("%d", cfg.Settings.MaxWorkers),
		"mode", *scanMode,
	)

	// Context oluştur — Settings.Timeout per-request timeout'tur,
	// pipeline context'i sınırsız olmalı (Ctrl+C ile iptal edilir).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handler: Ctrl+C / SIGTERM yakalıp context'i iptal et
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		color.Yellow("\n[!] Sinyal alındı: %v — tarama durduruluyor...", sig)
		cancel()		// İkinci sinyal gelirse zorla çık
		sig = <-sigCh
		color.Red("\n[!!] İkinci sinyal (%v) — zorla çıkılıyor!", sig)
		os.Exit(1)	}()

	// Mod → hangi phase'lerin çalışacağını belirle
	// -phase flag'i geriye dönük uyumluluk için hâlâ destekleniyor
	mode := strings.ToLower(*scanMode)
	if *phaseOnly != "" {
		mode = "p" + *phaseOnly // -phase 3 → p3
	}

	// Aktif phase setini hesapla
	activePhases := map[string]bool{}
	switch mode {
	case "full", "":
		for _, n := range []string{"1", "2", "3", "4", "5", "6"} {
			activePhases[n] = true
		}
	case "recon":
		activePhases["1"], activePhases["2"], activePhases["3"] = true, true, true
	case "web":
		activePhases["4"], activePhases["5"], activePhases["6"] = true, true, true
	default:
		// "1,2,3,4" veya "p1" veya "1-4" formatlarını destekle
		normalized := strings.ReplaceAll(mode, "p", "") // p1,p2 → 1,2
		// "1-4" aralık desteği
		if strings.Contains(normalized, "-") {
			parts := strings.SplitN(normalized, "-", 2)
			if len(parts) == 2 {
				start := strings.TrimSpace(parts[0])
				end := strings.TrimSpace(parts[1])
				inRange := false
				for _, n := range []string{"1", "2", "3", "4", "5", "6"} {
					if n == start {
						inRange = true
					}
					if inRange {
						activePhases[n] = true
					}
					if n == end {
						break
					}
				}
			}
		} else {
			// "1,2,3,4" veya tek "1"
			for _, part := range strings.Split(normalized, ",") {
				n := strings.TrimSpace(part)
				if n >= "1" && n <= "6" {
					activePhases[n] = true
				}
			}
		}
		if len(activePhases) == 0 {
			color.Red("[!] Geçersiz mod: %s", mode)
			color.Yellow("[i] Kullanım: -mode full | recon | web | 1,2,3 | 1-4 | p3")
			os.Exit(1)
		}
	}

	runPhase := func(n string) bool {
		return activePhases[n]
	}

	// Aktif phase listesini oluştur
	var activePhasesStr []string
	for _, n := range []string{"1", "2", "3", "4", "5", "6"} {
		if activePhases[n] {
			activePhasesStr = append(activePhasesStr, "P"+n)
		}
	}

	// Mod bilgisini göster
	modeLabel := map[string]string{
		"full":  "Full Scan (6 Phase)",
		"recon": "Recon Mode (Phase 1-2-3: Passive → DNS → Infra)",
		"web":   "Web Mode (Phase 4-5-6: Probe → Content → Fuzz)",
	}
	if label, ok := modeLabel[mode]; ok {
		color.Cyan("[*] Mod: %s\n", label)
	} else {
		color.Cyan("[*] Mod: Custom → %s\n", strings.Join(activePhasesStr, " → "))
	}

	// PhaseExecutor oluştur ve phase'leri kaydet
	executor := phases.NewPhaseExecutor(cfg)

	if runPhase("1") {
		executor.RegisterPhase(phases.NewPhase1Passive())
	}
	if runPhase("2") {
		executor.RegisterPhase(phases.NewPhase2DNS())
	}
	if runPhase("3") {
		executor.RegisterPhase(phases.NewPhase3Infrastructure())
	}
	if runPhase("4") {
		executor.RegisterPhase(phases.NewPhase4WebProbing())
	}
	if runPhase("5") {
		executor.RegisterPhase(phases.NewPhase5ContentAnalysis())
	}
	if runPhase("6") {
		executor.RegisterPhase(phases.NewPhase6ParameterFuzzing())
	}

	// Notification setup
	var notifier *notification.Notifier
	if cfg.Output.DiscordWebhook != "" || cfg.Output.SlackWebhook != "" {
		notifier = notification.NewNotifier(cfg.Output.DiscordWebhook, cfg.Output.SlackWebhook, cfg.Output.Verbose)
		// Başlangıç bildirimi gönder
		if err := notifier.SendStartNotification(*domain); err != nil && cfg.Output.Verbose {
			color.Yellow("[!] Notification gönderilemedi: %v", err)
		}
	}

	// Pipeline'ı çalıştır
	color.Cyan("\n" + strings.Repeat("=", 70))
	pipelineTitle := "BBFucker Pipeline Başlatılıyor - " + strings.Join(activePhasesStr, "→")
	color.Cyan("🚀 %s", pipelineTitle)
	color.Cyan(strings.Repeat("=", 70) + "\n")

	result, err := executor.ExecuteAll(ctx, *domain, outputDir)
	if err != nil {
		logger.Error("Pipeline hatası", err, "domain", *domain)
		// Hata bildirimi gönder
		if notifier != nil {
			notifier.SendErrorNotification(*domain, fmt.Sprintf("Pipeline hatası: %v", err))
		}
		log.Fatalf("Pipeline hatası: %v", err)
	}

	// Sonuçları kaydet
	saveResults(outputDir, result)

	// Screenshot'ları çek
	if cfg.Output.Screenshots && len(result.LiveHosts) > 0 {
		fmt.Println()
		printStep(0, 0, "SCREENSHOT CAPTURE")
		
		// Live host URL'lerini topla
		var urls []string
		for _, host := range result.LiveHosts {
			urls = append(urls, host.URL)
		}
		
		if cfg.Output.Verbose {
			color.Cyan("[*] %d URL için screenshot alınıyor...", len(urls))
		}
		
		capturer := screenshot.NewCapture(cfg)
		results := capturer.CaptureURLs(urls, outputDir)
		if len(results) > 0 {
			successCount := 0
			for _, r := range results {
				if r.Success {
					successCount++
				}
			}
			color.Green("[✓] %d/%d screenshot başarılı", successCount, len(urls))
		}
	}

	// Rapor oluştur
	fmt.Println()
	printStep(0, 0, "RAPOR OLUŞTURMA")
	generateReport(outputDir, result, cfg)

	// Tamamlanma bildirimi gönder
	if notifier != nil {
		vulns := result.GetAllVulnerabilities()
		criticalCount := 0
		highCount := 0
		for _, vuln := range vulns {
			if vuln.Severity == "critical" {
				criticalCount++
			} else if vuln.Severity == "high" {
				highCount++
			}
		}
		
		if err := notifier.SendCompleteNotification(
			*domain,
			len(result.GetAllSubdomains()),
			len(result.LiveHosts),
			len(vulns),
			criticalCount,
			highCount,
		); err != nil && cfg.Output.Verbose {
			color.Yellow("[!] Tamamlanma bildirimi gönderilemedi: %v", err)
		}
	}

	// Özet
	printSummary(result, outputDir)

	// Log özeti
	logger.Default().PrintSummary()
}

func saveResults(outputDir string, result *phases.PipelineResult) {
	// Subdomain'leri kaydet
	subdomains := result.GetAllSubdomains()
	saveList(filepath.Join(outputDir, "subdomains.txt"), subdomains)
	color.Green("[✓] %d subdomain kaydedildi", len(subdomains))

	// URL'leri kaydet
	urls := result.GetAllURLs()
	saveList(filepath.Join(outputDir, "urls.txt"), urls)
	color.Green("[✓] %d URL kaydedildi", len(urls))

	// Live host'ları kaydet
	var liveHosts []string
	for _, host := range result.LiveHosts {
		liveHosts = append(liveHosts, fmt.Sprintf("%s [%d]", host.URL, host.StatusCode))
	}
	if len(liveHosts) > 0 {
		saveList(filepath.Join(outputDir, "live_hosts.txt"), liveHosts)
		color.Green("[✓] %d live host kaydedildi", len(liveHosts))
	}

	// Açık portları kaydet
	var ports []string
	for _, port := range result.OpenPorts {
		ports = append(ports, fmt.Sprintf("%s:%d - %s", port.Host, port.Port, port.State))
	}
	if len(ports) > 0 {
		saveList(filepath.Join(outputDir, "ports.txt"), ports)
		color.Green("[✓] %d açık port kaydedildi", len(ports))
	}

	// Servis bilgilerini kaydet
	var services []string
	for _, svc := range result.Services {
		line := fmt.Sprintf("%s:%d - %s", svc.Host, svc.Port, svc.Name)
		if svc.Version != "" {
			line += " " + svc.Version
		}
		services = append(services, line)
	}
	if len(services) > 0 {
		saveList(filepath.Join(outputDir, "services.txt"), services)
		color.Green("[✓] %d servis kaydedildi", len(services))
	}

	// JavaScript dosyalarını kaydet
	if len(result.JSFiles) > 0 {
		saveList(filepath.Join(outputDir, "js_files.txt"), result.JSFiles)
		color.Green("[✓] %d JS dosyası kaydedildi", len(result.JSFiles))
	}

	// Endpoint'leri kaydet
	if len(result.Endpoints) > 0 {
		saveList(filepath.Join(outputDir, "endpoints.txt"), result.Endpoints)
		color.Green("[✓] %d endpoint kaydedildi", len(result.Endpoints))
	}

	// Parametreleri kaydet (URL -> param listesi)
	var paramLines []string
	for baseURL, params := range result.Parameters {
		for _, p := range params {
			paramLines = append(paramLines, baseURL+" -> "+p)
		}
	}
	if len(paramLines) > 0 {
		saveList(filepath.Join(outputDir, "parameters.txt"), paramLines)
		color.Green("[✓] %d parametre kaydedildi", len(paramLines))
	}

	// Güvenlik açıklarını kaydet
	var vulnLines []string
	for _, vuln := range result.GetAllVulnerabilities() {
		vulnLines = append(vulnLines, fmt.Sprintf("[%s] [%s] %s - %s",
			vuln.Severity, vuln.Type, vuln.Title, vuln.URL))
	}
	if len(vulnLines) > 0 {
		saveList(filepath.Join(outputDir, "vulnerabilities.txt"), vulnLines)
		color.Green("[✓] %d güvenlik açığı kaydedildi", len(vulnLines))
	}
}

func generateReport(outputDir string, result *phases.PipelineResult, cfg *config.Config) {
	// Eski reporter yapısını koruyalım (geriye dönük uyumluluk için)
	rep := reporter.NewReporter(outputDir, cfg.Output.Verbose)
	
	// Pipeline result'ı eski ScanResults formatına dönüştür
	legacyResults := &ScanResults{
		Domain:          result.Domain,
		ScanDate:        time.Now().Format("2006-01-02 15:04:05"),
		Subdomains:      result.GetAllSubdomains(),
		URLs:            result.GetAllURLs(),
		LiveHosts:       convertLiveHosts(result.LiveHosts),
		Vulnerabilities: convertVulnerabilities(result.GetAllVulnerabilities()),
		SensitiveFiles:  convertSensitiveFiles(result.SensitiveFiles),
	}

	// Statistikleri hesapla
	legacyResults.Stats.TotalSubdomains = len(result.GetAllSubdomains())
	legacyResults.Stats.TotalURLs = len(result.GetAllURLs())
	legacyResults.Stats.TotalVulns = len(result.GetAllVulnerabilities())
	
	for _, vuln := range result.GetAllVulnerabilities() {
		if vuln.Severity == "critical" {
			legacyResults.Stats.CriticalVulns++
		} else if vuln.Severity == "high" {
			legacyResults.Stats.HighVulns++
		}
	}

	rep.Generate(legacyResults)
}

func printSummary(result *phases.PipelineResult, outputDir string) {
	fmt.Println(color.GreenString("\n" + strings.Repeat("=", 70)))
	fmt.Println(color.GreenString("✅ PIPELINE TAMAMLANDI! ⚡"))
	fmt.Println(color.GreenString(strings.Repeat("=", 70)) + "\n")

	fmt.Println(color.CyanString("📊 ÖZET İSTATİSTİKLER:"))
	fmt.Printf("  └─ Subdomain: %s\n", color.YellowString("%d", len(result.GetAllSubdomains())))
	fmt.Printf("  └─ URL: %s\n", color.YellowString("%d", len(result.GetAllURLs())))
	fmt.Printf("  └─ Aktif Host: %s\n", color.YellowString("%d", len(result.LiveHosts)))
	fmt.Printf("  └─ Açık Port: %s\n", color.YellowString("%d", len(result.OpenPorts)))
	fmt.Printf("  └─ Servis: %s\n", color.YellowString("%d", len(result.Services)))
	fmt.Printf("  └─ JS Dosyası: %s\n", color.YellowString("%d", len(result.JSFiles)))
	fmt.Printf("  └─ Endpoint: %s\n", color.YellowString("%d", len(result.Endpoints)))
	totalParams := 0
	for _, params := range result.Parameters {
		totalParams += len(params)
	}
	fmt.Printf("  └─ Parametre: %s\n", color.YellowString("%d", totalParams))

	// Güvenlik açıkları özeti
	vulns := result.GetAllVulnerabilities()
	if len(vulns) > 0 {
		bySeverity := make(map[string]int)
		for _, vuln := range vulns {
			bySeverity[vuln.Severity]++
		}

		fmt.Printf("\n  %s\n", color.RedString("🔴 Toplam Güvenlik Açığı: %d", len(vulns)))
		if count, ok := bySeverity["critical"]; ok && count > 0 {
			fmt.Printf("    └─ Critical: %s\n", color.RedString("%d", count))
		}
		if count, ok := bySeverity["high"]; ok && count > 0 {
			fmt.Printf("    └─ High: %s\n", color.RedString("%d", count))
		}
		if count, ok := bySeverity["medium"]; ok && count > 0 {
			fmt.Printf("    └─ Medium: %s\n", color.YellowString("%d", count))
		}
		if count, ok := bySeverity["low"]; ok && count > 0 {
			fmt.Printf("    └─ Low: %s\n", color.CyanString("%d", count))
		}

		// En kritik bulguları göster
		fmt.Println(color.RedString("\n🔍 ÖNE ÇIKAN BULGULAR:"))
		shown := 0
		for _, severity := range []string{"critical", "high", "medium"} {
			for _, vuln := range vulns {
				if vuln.Severity == severity && shown < 10 {
					urlStr := vuln.URL
					if len(urlStr) > 60 {
						urlStr = urlStr[:60] + "..."
					}
					fmt.Printf("  • [%s] %s: %s\n", strings.ToUpper(vuln.Severity), vuln.Type, urlStr)
					if vuln.Description != "" && shown < 3 {
						fmt.Printf("    └─ %s\n", vuln.Description)
					}
					shown++
				}
			}
		}
	} else {
		fmt.Printf("\n  %s\n", color.GreenString("✅ Güvenlik açığı bulunamadı"))
	}

	// Phase istatistikleri
	fmt.Println(color.CyanString("\n📈 PHASE İSTATİSTİKLERİ:"))
	for _, output := range result.PhaseOutputs {
		duration := fmt.Sprintf("%.2fs", output.Statistics.Duration)
		toolCount := len(output.Statistics.ToolsUsed)
		fmt.Printf("  └─ %s (%s, %d araç)\n", output.PhaseName, duration, toolCount)
		if len(output.Statistics.Extra) > 0 {
			for key, val := range output.Statistics.Extra {
				if val > 0 {
					fmt.Printf("      • %s: %d\n", key, val)
				}
			}
		}
	}

	fmt.Println(color.GreenString("\n📁 Çıktı Dizini: ") + outputDir)
	fmt.Printf("  └─ HTML Rapor: %s\n", filepath.Join(outputDir, "report.html"))
	fmt.Printf("  └─ JSON Rapor: %s\n", filepath.Join(outputDir, "report.json"))
	fmt.Printf("  └─ Özet: %s\n\n", filepath.Join(outputDir, "summary.txt"))
}

func printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██████╗     ███████╗██╗   ██╗ ██████╗██╗  ██╗        ║
║   ██╔══██╗██╔══██╗    ██╔════╝██║   ██║██╔════╝██║ ██╔╝        ║
║   ██████╔╝██████╔╝    █████╗  ██║   ██║██║     █████╔╝         ║
║   ██╔══██╗██╔══██╗    ██╔══╝  ██║   ██║██║     ██╔═██╗         ║
║   ██████╔╝██████╔╝    ██║     ╚██████╔╝╚██████╗██║  ██╗        ║
║   ╚═════╝ ╚═════╝     ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝        ║
║                                                                  ║
║        🚀 Go Edition - ULTRA FAST! ⚡                            ║
║        6-Phase Professional Bug Bounty Pipeline                  ║
║        Passive → DNS → Infrastructure → Web → Content → Fuzz    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`
	color.Cyan(banner)
}

func printStep(step, total int, title string) {
	if step > 0 {
		fmt.Println(color.CyanString("\n" + strings.Repeat("=", 70)))
		fmt.Printf("%s\n", color.CyanString("[ADIM %d/%d] %s", step, total, title))
		fmt.Println(color.CyanString(strings.Repeat("=", 70)) + "\n")
	} else {
		fmt.Println(color.CyanString("\n" + strings.Repeat("=", 70)))
		fmt.Printf("%s\n", color.CyanString("[%s]", title))
		fmt.Println(color.CyanString(strings.Repeat("=", 70)) + "\n")
	}
}

func saveList(filePath string, items []string) {
	if len(items) == 0 {
		return
	}
	f, err := os.Create(filePath)
	if err != nil {
		logger.Error("Dosya oluşturulamadı", err, "path", filePath)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, item := range items {
		fmt.Fprintln(w, item)
	}
	if err := w.Flush(); err != nil {
		logger.Error("Dosya yazma hatası", err, "path", filePath)
	}
}

// ============================================================================
// Helper Types & Converters (Geriye dönük uyumluluk için)
// ============================================================================

type ScanResults struct {
	Domain          string                   `json:"domain"`
	ScanDate        string                   `json:"scan_date"`
	Subdomains      []string                 `json:"subdomains"`
	URLs            []string                 `json:"urls"`
	LiveHosts       []LiveHostLegacy         `json:"live_hosts"`
	Vulnerabilities []VulnerabilityLegacy    `json:"vulnerabilities"`
	SensitiveFiles  []SensitiveFileLegacy    `json:"sensitive_files"`
	Stats           struct {
		TotalSubdomains    int `json:"total_subdomains"`
		TotalURLs          int `json:"total_urls"`
		TotalVulns         int `json:"total_vulnerabilities"`
		CriticalVulns      int `json:"critical_vulns"`
		HighVulns          int `json:"high_vulns"`
	} `json:"stats"`
}

type LiveHostLegacy struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	WAF           string   `json:"waf,omitempty"`
	CMS           string   `json:"cms,omitempty"`
	CMSVersion    string   `json:"cms_version,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	ContentLength int      `json:"content_length"`
}

type VulnerabilityLegacy struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter,omitempty"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
}

type SensitiveFileLegacy struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Size    int    `json:"size"`
	Content string `json:"content"`
}

func convertLiveHosts(hosts []phases.LiveHost) []LiveHostLegacy {
	result := make([]LiveHostLegacy, len(hosts))
	for i, h := range hosts {
		result[i] = LiveHostLegacy{
			URL:           h.URL,
			StatusCode:    h.StatusCode,
			Title:         h.Title,
			WAF:           h.WAF,
			CMS:           h.CMS,
			CMSVersion:    h.CMSVersion,
			Technologies:  h.Technologies,
			ContentLength: h.ContentLength,
		}
	}
	return result
}

func convertVulnerabilities(vulns []phases.Vulnerability) []VulnerabilityLegacy {
	result := make([]VulnerabilityLegacy, len(vulns))
	for i, v := range vulns {
		result[i] = VulnerabilityLegacy{
			Type:        v.Type,
			URL:         v.URL,
			Parameter:   v.Parameter,
			Severity:    v.Severity,
			Description: v.Description,
		}
	}
	return result
}

func convertSensitiveFiles(files []phases.SensitiveFile) []SensitiveFileLegacy {
	result := make([]SensitiveFileLegacy, len(files))
	for i, f := range files {
		result[i] = SensitiveFileLegacy{
			URL:     f.URL,
			Type:    f.Type,
			Size:    f.Size,
			Content: f.Content,
		}
	}
	return result
}

// ============================================================================
// Güvenlik — Domain Doğrulama
// ============================================================================

// domainRegex — RFC 952/1123 uyumlu domain pattern
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// validateDomain, domain girişini güvenlik açısından doğrular.
// Komut enjeksiyonu, path traversal ve SSRF'e karşı koruma sağlar.
func validateDomain(domain string) error {
	// Boşluk/kontrol karakteri kontrolü
	if strings.ContainsAny(domain, " \t\r\n") {
		return fmt.Errorf("domain boşluk veya kontrol karakteri içeremez")
	}
	// Path traversal kontrolü
	if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
		return fmt.Errorf("domain path ayırıcı veya '..' içeremez: %s", domain)
	}
	// Shell metakarakter kontrolü
	if strings.ContainsAny(domain, ";|&$`\"'(){}[]<>!#~") {
		return fmt.Errorf("domain özel karakter içeremez: %s", domain)
	}
	// Uzunluk kontrolü (DNS max 253)
	if len(domain) > 253 || len(domain) < 3 {
		return fmt.Errorf("domain uzunluğu geçersiz (3-253 karakter): %d", len(domain))
	}
	// Regex format kontrolü
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("geçersiz domain formatı: %s", domain)
	}
	// URL scheme kontrolü — sadece domain kabul et
	if strings.Contains(domain, "://") {
		parsed, err := url.Parse(domain)
		if err == nil && parsed.Host != "" {
			return fmt.Errorf("domain URL olmamalı, sadece domain girin: %s (hostname: %s)", domain, parsed.Host)
		}
	}
	return nil
}
