package phases

import (
	"bbfucker/pkg/config"
	"bbfucker/pkg/httpprobe"
	"bbfucker/pkg/logger"
	"bbfucker/pkg/nuclei"
	"bbfucker/pkg/subjack"
	"bbfucker/pkg/wafguard"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Phase 4: Web Probing & Vulnerability Scanning
// ============================================================================

type Phase4WebProbing struct {
	cfg *config.Config
}

func NewPhase4WebProbing() *Phase4WebProbing {
	return &Phase4WebProbing{}
}

func (p *Phase4WebProbing) Name() string {
	return "Phase 4: Web Probing & Vulnerability Scanning"
}

func (p *Phase4WebProbing) Description() string {
	return "HTTPX probing, Nuclei CVE scanning, subdomain takeover detection"
}

func (p *Phase4WebProbing) IsEnabled(cfg *config.Config) bool {
	return cfg.Phase4WebProbing.Enabled
}

func (p *Phase4WebProbing) Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error) {
	p.cfg = cfg
	startTime := time.Now()
	log := logger.Default().With("phase", "4-webprobe", "domain", input.Domain)
	
	color.Cyan("\n[PHASE 4] %s", p.Name())
	color.Cyan("═══════════════════════════════════════════════════════════")
	
	output := &PhaseOutput{
		PhaseName:       p.Name(),
		LiveHosts:       make([]LiveHost, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Findings:        make([]Finding, 0),
		Statistics: Statistics{
			ToolsUsed: make([]string, 0),
			Extra:     make(map[string]int),
		},
		Extra: make(map[string]interface{}),
	}
	
	// Step 4.1: HTTP Probing (HTTPX)
	if cfg.Phase4WebProbing.HTTPProbe.Enabled {
		color.Yellow("\n[*] Step 4.1: HTTP Probing (HTTPX)")
		liveHosts := p.probeHosts(ctx, input.ResolvedDomains)
		output.LiveHosts = liveHosts
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "httpx")
		output.Statistics.Extra["live_hosts"] = len(liveHosts)
		color.Green("[✓] Found %d live web hosts", len(liveHosts))
	}
	
	// Step 4.2: Nuclei CVE Scanning
	if cfg.Phase4WebProbing.Nuclei.Enabled && len(output.LiveHosts) > 0 {
		color.Yellow("\n[*] Step 4.2: Nuclei Vulnerability Scanning")
		vulns := p.scanWithNuclei(ctx, output.LiveHosts)
		output.Vulnerabilities = append(output.Vulnerabilities, vulns...)
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "nuclei")
		output.Statistics.Extra["nuclei_vulns"] = len(vulns)
		color.Green("[✓] Nuclei found %d vulnerabilities", len(vulns))
	}
	
	// Step 4.3: Subdomain Takeover Detection
	if cfg.Phase4WebProbing.Takeover.Enabled {
		color.Yellow("\n[*] Step 4.3: Subdomain Takeover Detection")
		takeovers := p.checkTakeover(ctx, input.ResolvedDomains)
		if len(takeovers) > 0 {
			for _, t := range takeovers {
				output.Vulnerabilities = append(output.Vulnerabilities, Vulnerability{
					Type:        "subdomain_takeover",
					Severity:    "high",
					URL:         t,
					Description: "Vulnerable to subdomain takeover",
				})
			}
		}
		output.Statistics.ToolsUsed = append(output.Statistics.ToolsUsed, "subjack", "subzy")
		output.Statistics.Extra["takeovers"] = len(takeovers)
		color.Green("[✓] Checked for takeovers: %d vulnerable", len(takeovers))
	}

	// Step 4.4: CMS & WAF Analysis
	color.Yellow("\n[*] Step 4.4: CMS & WAF Analysis")
	wafCount, cmsCount := 0, 0
	cmsSummary := make(map[string]int)
	wafHosts := make(map[string]string) // url → WAF adı (downstream phases için)
	toolsAvailable := p.checkCMSWAFTools()
	if !toolsAvailable && p.cfg.Output.Verbose {
		color.Yellow("  [!] wafw00f ve whatweb kurulu değil - sadece temel HTTP fingerprinting")
	}
	for _, host := range output.LiveHosts {
		if host.WAF != "" {
			wafCount++
			wafHosts[host.URL] = host.WAF
			if p.cfg.Output.Verbose {
				color.Red("  [WAF] %s → %s tespit edildi", host.URL, host.WAF)
			}
		}
		if host.CMS != "" {
			cmsCount++
			cmsSummary[host.CMS]++
			// CMS'e özgül güvenlik açığı taraması
			vulns := p.cmsSpecificScan(ctx, host)
			output.Vulnerabilities = append(output.Vulnerabilities, vulns...)
		}
	}
	for cms, count := range cmsSummary {
		color.Green("  [CMS] %s: %d host", cms, count)
	}
	if wafCount == 0 && cmsCount == 0 && toolsAvailable {
		color.Yellow("  [i] WAF/CMS tespit edilemedi (temiz site veya olağan yapılandırma)")
	}
	output.Statistics.Extra["waf_detected"] = wafCount
	output.Statistics.Extra["cms_detected"] = cmsCount
	color.Green("[✓] WAF detected: %d hosts | CMS detected: %d hosts", wafCount, cmsCount)

	// WAF tespit edildiyse sonraki fazlar için uyar ve stratejiyi belirt
	if wafCount > 0 {
		color.Red("\n[⚑] WAF KORUMASI TESPİT EDİLDİ (%d host)", wafCount)
		color.Yellow("  → Sonraki fazlarda agresif tarama durdurulacak")
		color.Yellow("  → Nuclei/Dalfox stealth moda geçecek (düşük hız, WAF evasion)")
		color.Yellow("  → FFUF directory fuzzing WAF'lı hostlarda atlanacak")
		// WAF host haritasını downstream fazlar için output'a ekle
		output.Extra["waf_hosts"] = wafHosts
	}

	output.Statistics.TotalItems = len(output.LiveHosts) + len(output.Vulnerabilities)
	output.Statistics.Duration = time.Since(startTime).Seconds()

	log.Infof("Phase 4 tamamlandı: %d live host, %d zafiyet, %.2fs", len(output.LiveHosts), len(output.Vulnerabilities), output.Statistics.Duration)
	color.Green("\n[✓] Phase 4 Complete: %d live hosts, %d vulnerabilities", len(output.LiveHosts), len(output.Vulnerabilities))
	color.Cyan("═══════════════════════════════════════════════════════════\n")
	
	return output, nil
}

// ============================================================================
// Web Probing & Scanning Implementations
// ============================================================================

func (p *Phase4WebProbing) probeHosts(ctx context.Context, hosts []string) []LiveHost {
	prober := httpprobe.NewProber(p.cfg)
	liveHosts := prober.ProbeHosts(hosts)

	result := make([]LiveHost, len(liveHosts))
	for i, host := range liveHosts {
		result[i] = LiveHost{
			URL:           host.URL,
			Host:          host.Host,
			StatusCode:    host.StatusCode,
			Title:         host.Title,
			Server:        host.Server,
			Technologies:  host.Technologies,
			ContentLength: host.ContentLength,
			WAF:           host.WAF,
			CMS:           host.CMS,
			CMSVersion:    host.CMSVersion,
		}
		if p.cfg.Output.Verbose {
			extra := ""
			if host.WAF != "" {
				extra += " [WAF: " + host.WAF + "]"
			}
			if host.CMS != "" {
				extra += " [CMS: " + host.CMS
				if host.CMSVersion != "" {
					extra += " " + host.CMSVersion
				}
				extra += "]"
			}
			color.Green("  [%d] %s%s", host.StatusCode, host.URL, extra)
		}
	}

	return result
}

func (p *Phase4WebProbing) scanWithNuclei(ctx context.Context, hosts []LiveHost) []Vulnerability {
	// Use existing nuclei module
	nucleiScanner := nuclei.NewScanner(p.cfg)
	
	if !nucleiScanner.CheckInstalled() {
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] Nuclei not installed, skipping...")
		}
		return []Vulnerability{}
	}
	
	// Ensure templates are updated
	nucleiScanner.EnsureTemplates()

	// WAF korumalı ve normal hostları ayır
	guard := wafguard.New()
	var normalTargets []string
	var stealthTargets []string

	for _, host := range hosts {
		if host.WAF != "" {
			guard.Register(host.URL, host.WAF)
			stealthTargets = append(stealthTargets, host.URL)
		} else {
			normalTargets = append(normalTargets, host.URL)
		}
	}

	var allFindings []nuclei.Finding

	// Normal hostlar — standart tarama
	if len(normalTargets) > 0 {
		allFindings = append(allFindings, nucleiScanner.ScanTargets(ctx, normalTargets)...)
	}

	// WAF korumalı hostlar — stealth tarama (IsKilled kontrolü ile)
	if len(stealthTargets) > 0 {
		color.Yellow("  [!] %d WAF korumalı host için stealth nuclei modu aktif", len(stealthTargets))
		var activeTargets []string
		for _, t := range stealthTargets {
			if guard.IsKilled(t) {
				color.Red("  [\u2717] %s — 3+ blok tespit edildi, tarama durduruldu", t)
				continue
			}
			activeTargets = append(activeTargets, t)
		}
		if len(activeTargets) > 0 {
			allFindings = append(allFindings, nucleiScanner.ScanTargetsStealth(ctx, activeTargets)...)
		}
	}
	
	// Convert nuclei.Finding to phases.Vulnerability
	vulns := make([]Vulnerability, len(allFindings))
	for i, finding := range allFindings {
		vulns[i] = Vulnerability{
			Type:        "nuclei_" + finding.TemplateID,
			Severity:    finding.Severity,
			Title:       finding.TemplateName,
			URL:         finding.Host,
			Description: finding.Description,
			Evidence:    finding.MatchedAt,
		}
	}
	
	return vulns
}

func (p *Phase4WebProbing) checkTakeover(ctx context.Context, hosts []string) []string {
	// Use existing subjack module
	subjackScanner := subjack.NewScanner(p.cfg)

	takeovers := subjackScanner.CheckTakeover(hosts)

	vulnerableHosts := make([]string, 0)
	for _, takeover := range takeovers {
		if takeover.Vulnerable {
			vulnerableHosts = append(vulnerableHosts, takeover.Subdomain)
			if p.cfg.Output.Verbose {
				color.Red("  [!] TAKEOVER: %s via %s", takeover.Subdomain, takeover.Service)
			}
		}
	}

	return vulnerableHosts
}

// cmsSpecificScan — CMS'e özgü araçları çalıştırır:
//   - WordPress → wpscan (versiyon, plugin, tema, kullanıcı enum, zafiyet)
//   - Joomla / Drupal / Magento / vb. → nuclei CMS-tag taraması
func (p *Phase4WebProbing) cmsSpecificScan(ctx context.Context, host LiveHost) []Vulnerability {
	switch host.CMS {
	case "WordPress":
		return p.scanWordPress(ctx, host)
	default:
		return p.scanCMSWithNuclei(ctx, host)
	}
}

// scanWordPress — wpscan ile WordPress'e özel tam tarama yapar.
func (p *Phase4WebProbing) scanWordPress(ctx context.Context, host LiveHost) []Vulnerability {
	if p.cfg.Output.Verbose {
		color.Cyan("  [WPScan] %s taranıyor...", host.URL)
	}

	args := []string{
		"--url", host.URL,
		"--enumerate", "ap,at,u",
		"--format", "json",
		"--no-banner",
		"--disable-tls-checks",
	}
	if token := p.cfg.Phase4WebProbing.WPScanAPIToken; token != "" {
		args = append(args, "--api-token", token)
	}

	out, err := exec.CommandContext(ctx, "wpscan", args...).Output()
	if err != nil && len(out) == 0 {
		color.Yellow("  [!] wpscan çalıştırılamadı: %v", err)
		return nil
	}

	// JSON parse
	var result struct {
		Version *struct {
			Number          string `json:"number"`
			Vulnerabilities []struct {
				Title   string `json:"title"`
				FixedIn string `json:"fixed_in"`
			} `json:"vulnerabilities"`
		} `json:"version"`
		InterestingFindings []struct {
			Type        string `json:"type"`
			URL         string `json:"url"`
			ToS         string `json:"to_s"`
			Interesting bool   `json:"interesting"`
		} `json:"interesting_findings"`
		Plugins map[string]struct {
			Slug            string `json:"slug"`
			Vulnerabilities []struct {
				Title   string `json:"title"`
				FixedIn string `json:"fixed_in"`
				CVSSScore float64 `json:"cvss"`
			} `json:"vulnerabilities"`
		} `json:"plugins"`
		Users map[string]struct {
			ID    int    `json:"id"`
			Login string `json:"username"`
		} `json:"users"`
	}

	if err := json.Unmarshal(out, &result); err != nil {
		color.Yellow("  [!] wpscan JSON parse hatası: %v", err)
		return nil
	}

	var vulns []Vulnerability

	// WordPress versiyon zafiyetleri
	if result.Version != nil {
		for _, v := range result.Version.Vulnerabilities {
			vulns = append(vulns, Vulnerability{
				Type:        "wordpress_core",
				Severity:    "high",
				Title:       v.Title,
				URL:         host.URL,
				Description: fmt.Sprintf("WordPress %s — Fixed in: %s", result.Version.Number, v.FixedIn),
			})
			if p.cfg.Output.Verbose {
				color.Red("  [WP-CORE] %s", v.Title)
			}
		}
	}

	// Plugin zafiyetleri
	for _, plugin := range result.Plugins {
		for _, v := range plugin.Vulnerabilities {
			sev := "medium"
			if v.CVSSScore >= 9.0 {
				sev = "critical"
			} else if v.CVSSScore >= 7.0 {
				sev = "high"
			} else if v.CVSSScore >= 4.0 {
				sev = "medium"
			} else if v.CVSSScore > 0 {
				sev = "low"
			}
			vulns = append(vulns, Vulnerability{
				Type:        "wordpress_plugin",
				Severity:    sev,
				Title:       v.Title,
				URL:         host.URL,
				Description: fmt.Sprintf("Plugin: %s — Fixed in: %s", plugin.Slug, v.FixedIn),
			})
			if p.cfg.Output.Verbose {
				color.Red("  [WP-PLUGIN][%s] %s", plugin.Slug, v.Title)
			}
		}
	}

	// Kullanıcı enumeration
	if len(result.Users) > 0 {
		userList := make([]string, 0, len(result.Users))
		for login := range result.Users {
			userList = append(userList, login)
		}
		vulns = append(vulns, Vulnerability{
			Type:        "wordpress_user_enum",
			Severity:    "info",
			Title:       "WordPress Kullanıcı Enum",
			URL:         host.URL,
			Description: fmt.Sprintf("Bulunan kullanıcılar: %s", strings.Join(userList, ", ")),
		})
		if p.cfg.Output.Verbose {
			color.Yellow("  [WP-USERS] %s", strings.Join(userList, ", "))
		}
	}

	color.Green("  [WPScan] %d zafiyet bulundu", len(vulns))
	return vulns
}

// scanCMSWithNuclei — Joomla/Drupal/Magento vb. için nuclei CMS tag taraması.
func (p *Phase4WebProbing) scanCMSWithNuclei(ctx context.Context, host LiveHost) []Vulnerability {
	nucleiScanner := nuclei.NewScanner(p.cfg)
	if !nucleiScanner.CheckInstalled() {
		return nil
	}

	cmsTagMap := map[string][]string{
		"Joomla":     {"joomla"},
		"Drupal":     {"drupal"},
		"Magento":    {"magento"},
		"PrestaShop": {"prestashop"},
		"OpenCart":   {"opencart"},
		"TYPO3":      {"typo3"},
		"Laravel":    {"laravel", "php"},
		"Django":     {"django", "python"},
	}

	tags, ok := cmsTagMap[host.CMS]
	if !ok {
		return nil
	}

	if p.cfg.Output.Verbose {
		color.Cyan("  [Nuclei/%s] tag=%v ile taranıyor...", host.CMS, tags)
	}

	findings := nucleiScanner.ScanTargetsWithTags(ctx, []string{host.URL}, tags)

	vulns := make([]Vulnerability, 0, len(findings))
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "medium"
		}
		vulns = append(vulns, Vulnerability{
			Type:        "cms_" + f.TemplateID,
			Severity:    sev,
			Title:       f.TemplateName,
			URL:         f.Host,
			Description: f.Description,
			Evidence:    f.MatchedAt,
		})
		if p.cfg.Output.Verbose {
			color.Red("  [CMS-VULN] [%s] %s — %s", sev, f.TemplateName, f.Host)
		}
	}

	return vulns
}

// checkCMSWAFTools verifies if external tools are available and provides helpful feedback
func (p *Phase4WebProbing) checkCMSWAFTools() bool {
	type tool struct{ bin, install string }
	tools := []tool{
		{"wafw00f", "apt install wafw00f"},
		{"whatweb", "apt install whatweb"},
		{"wpscan", "gem install wpscan"},
	}
	allOK := true
	if p.cfg.Output.Verbose {
		color.Yellow("  [i] Web analiz araçları kontrol ediliyor...")
	}
	for _, t := range tools {
		_, err := exec.LookPath(t.bin)
		if err != nil {
			allOK = false
			if p.cfg.Output.Verbose {
				color.Yellow("    ! %s kurulu değil  →  %s", t.bin, t.install)
			}
		} else if p.cfg.Output.Verbose {
			color.Green("    ✓ %s hazır", t.bin)
		}
	}
	return allOK
}
