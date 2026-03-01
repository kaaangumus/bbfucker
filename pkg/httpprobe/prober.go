package httpprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
)

type LiveHost struct {
	URL            string   `json:"url"`
	Host           string   `json:"host"`
	Scheme         string   `json:"scheme"`
	StatusCode     int      `json:"status_code"`
	ContentLength  int      `json:"content_length"`
	Title          string   `json:"title"`
	Server         string   `json:"server"`
	Technologies   []string `json:"technologies"`
	ResponseTimeMs int64    `json:"response_time_ms"`
	WAF            string   `json:"waf,omitempty"`
	CMS            string   `json:"cms,omitempty"`
	CMSVersion     string   `json:"cms_version,omitempty"`
}

type Prober struct {
	cfg    *config.Config
	client *http.Client
}

func NewProber(cfg *config.Config) *Prober {
	return &Prober{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.Settings.Timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: *cfg.Settings.InsecureSkipVerify},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *Prober) ProbeHosts(hosts []string) []LiveHost {
	// Önce httpx CLI'ı dene (çok daha hızlı ve güvenilir)
	if _, err := exec.LookPath("httpx"); err == nil {
		if results := p.probeWithHTTPX(hosts); len(results) > 0 {
			return results
		}
		if p.cfg.Output.Verbose {
			color.Yellow("  [!] httpx sonuç döndürmedi, Go HTTP fallback kullanılıyor...")
		}
	} else if p.cfg.Output.Verbose {
		color.Yellow("  [!] httpx bulunamadı, Go HTTP fallback kullanılıyor...")
	}

	// Fallback: Go HTTP client ile probe
	return p.probeWithGoHTTP(hosts)
}

// probeWithHTTPX — httpx CLI ile hızlı HTTP probing
func (p *Prober) probeWithHTTPX(hosts []string) []LiveHost {
	if len(hosts) == 0 {
		return nil
	}

	// Temp dosyaya host listesi yaz
	tmpFile, err := os.CreateTemp("", "bbfucker_httpx_*.txt")
	if err != nil {
		return nil
	}
	defer os.Remove(tmpFile.Name())
	for _, h := range hosts {
		fmt.Fprintln(tmpFile, h)
	}
	tmpFile.Close()

	// httpx komutu: JSON çıktı, title, status-code, server, tech-detect, content-length
	args := []string{
		"-l", tmpFile.Name(),
		"-json",
		"-title",
		"-status-code",
		"-server",
		"-content-length",
		"-tech-detect",
		"-follow-redirects",
		"-silent",
		"-threads", fmt.Sprintf("%d", p.cfg.Settings.MaxWorkers),
		"-timeout", fmt.Sprintf("%d", p.cfg.Settings.Timeout),
		"-no-color",
	}

	// httpx için global timeout: settings.timeout × host sayısı, min 120s
	timeoutSec := max(120, p.cfg.Settings.Timeout*len(hosts))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "httpx", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if p.cfg.Output.Verbose {
		color.Cyan("  [*] httpx ile %d host probe ediliyor...", len(hosts))
	}

	if err := cmd.Run(); err != nil {
		logger.Warnf("httpx hatası: %v (hosts=%d)", err, len(hosts))
		return nil
	}

	// httpx JSON çıktısını parse et
	var liveHosts []LiveHost
	scanner := bufio.NewScanner(&stdout)
	// Büyük satırlar için buffer artır
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry struct {
			URL           string   `json:"url"`
			Host          string   `json:"host"`
			StatusCode    int      `json:"status_code"`
			Title         string   `json:"title"`
			Server        string   `json:"webserver"`
			ContentLength int      `json:"content_length"`
			Technologies  []string `json:"tech"`
			Scheme        string   `json:"scheme"`
		}

		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			logger.Debugf("httpx JSON parse hatası: %v", err)
			continue
		}

		if entry.URL == "" {
			continue
		}

		host := &LiveHost{
			URL:           entry.URL,
			Host:          entry.Host,
			Scheme:        entry.Scheme,
			StatusCode:    entry.StatusCode,
			Title:         entry.Title,
			Server:        entry.Server,
			ContentLength: entry.ContentLength,
			Technologies:  entry.Technologies,
		}

		// CMS tespiti (tech listesinden)
		for _, tech := range entry.Technologies {
			techLow := strings.ToLower(tech)
			switch {
			case strings.Contains(techLow, "wordpress"):
				host.CMS = "WordPress"
			case strings.Contains(techLow, "joomla"):
				host.CMS = "Joomla"
			case strings.Contains(techLow, "drupal"):
				host.CMS = "Drupal"
			case strings.Contains(techLow, "shopify"):
				host.CMS = "Shopify"
			case strings.Contains(techLow, "magento"):
				host.CMS = "Magento"
			case strings.Contains(techLow, "laravel"):
				host.CMS = "Laravel"
			case strings.Contains(techLow, "django"):
				host.CMS = "Django"
			}
			// WAF tespiti
			switch {
			case strings.Contains(techLow, "cloudflare"):
				host.WAF = "Cloudflare"
			case strings.Contains(techLow, "akamai"):
				host.WAF = "Akamai"
			case strings.Contains(techLow, "sucuri"):
				host.WAF = "Sucuri"
			case strings.Contains(techLow, "imperva") || strings.Contains(techLow, "incapsula"):
				host.WAF = "Imperva"
			case strings.Contains(techLow, "f5") || strings.Contains(techLow, "big-ip"):
				host.WAF = "F5 BIG-IP"
			case strings.Contains(techLow, "aws"):
				host.WAF = "AWS WAF"
			}
		}

		liveHosts = append(liveHosts, *host)

		if p.cfg.Output.Verbose {
			extra := ""
			if host.WAF != "" {
				extra += " [WAF: " + host.WAF + "]"
			}
			if host.CMS != "" {
				extra += " [CMS: " + host.CMS + "]"
			}
			color.Green("  [%d] %s%s", host.StatusCode, host.URL, extra)
		}
	}

	if p.cfg.Output.Verbose {
		color.Green("  [✓] httpx: %d live host bulundu", len(liveHosts))
	}

	return liveHosts
}

// probeWithGoHTTP — httpx yoksa Go HTTP client ile fallback
func (p *Prober) probeWithGoHTTP(hosts []string) []LiveHost {
	var liveHosts []LiveHost
	var mu sync.Mutex
	var wg sync.WaitGroup

	workerCount := p.cfg.Settings.MaxWorkers
	if workerCount <= 0 {
		workerCount = 50
	}
	jobs := make(chan string, workerCount)

	// Sabit sayıda worker başlat
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				// HTTPS dene önce
				if result := p.probe(h, "https"); result != nil {
					mu.Lock()
					liveHosts = append(liveHosts, *result)
					mu.Unlock()
					if p.cfg.Output.Verbose {
						color.Green("[✓] %s [%d]", result.URL, result.StatusCode)
					}
					continue
				}

				// HTTP dene
				if result := p.probe(h, "http"); result != nil {
					mu.Lock()
					liveHosts = append(liveHosts, *result)
					mu.Unlock()
					if p.cfg.Output.Verbose {
						color.Green("[✓] %s [%d]", result.URL, result.StatusCode)
					}
				}
			}
		}()
	}

	// İşleri kanala gönder
	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)

	wg.Wait()
	return liveHosts
}

func (p *Prober) probe(host, scheme string) *LiveHost {
	url := fmt.Sprintf("%s://%s", scheme, host)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Debugf("HTTP request oluşturulamadı: %s - %v", url, err)
		return nil
	}
	req.Header.Set("User-Agent", p.cfg.Settings.UserAgent)

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		logger.Debugf("HTTP bağlantı hatası: %s - %v", url, err)
		return nil
	}
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()

	// OOM koruması: maksimum 10MB body oku
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		logger.Debugf("body okuma hatası: %s - %v", url, err)
		return nil
	}

	bodyStr := string(body)

	waf := runWAFW00F(url)
	cms, cmsVersion, extraTechs := runWhatWeb(url)

	result := &LiveHost{
		URL:            url,
		Host:           host,
		Scheme:         scheme,
		StatusCode:     resp.StatusCode,
		ContentLength:  len(body),
		Server:         resp.Header.Get("Server"),
		ResponseTimeMs: elapsed,
		Title:          extractTitle(bodyStr),
		Technologies:   mergeTechs(detectTechnologies(resp, bodyStr), extraTechs),
		WAF:            waf,
		CMS:            cms,
		CMSVersion:     cmsVersion,
	}

	return result
}

func extractTitle(html string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return "No Title"
	}
	title := doc.Find("title").Text()
	if title == "" {
		return "No Title"
	}
	return strings.TrimSpace(title)
}

// ─── WAF Detection — wafw00f ─────────────────────────────────────────────────

// runWAFW00F wafw00f CLI aracını çalıştırarak WAF tespiti yapar.
func runWAFW00F(targetURL string) string {
	// wafw00f kurulu mu kontrol et
	if _, err := exec.LookPath("wafw00f"); err != nil {
		// fmt.Printf("[DEBUG] wafw00f not found for %s\n", targetURL)
		return "" // Araç yok, sessizce dön
	}

	tmp, err := os.CreateTemp("", "wafw00f-*.json")
	if err != nil {
		logger.Debugf("wafw00f temp dosya hatası: %v", err)
		return ""
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	ctxWaf, cancelWaf := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelWaf()

	cmd := exec.CommandContext(ctxWaf, "wafw00f", "-f", "json", "-o", tmp.Name(), targetURL)
	cmd.Run()

	data, err := os.ReadFile(tmp.Name())
	if err != nil || len(data) == 0 {
		return ""
	}

	// wafw00f JSON çıktısı: [{"url":"...","detected":true,"firewall":"..."}]
	var results []struct {
		Firewall string `json:"firewall"`
		Detected bool   `json:"detected"`
	}
	if json.Unmarshal(data, &results) == nil && len(results) > 0 && results[0].Detected {
		return results[0].Firewall
	}
	// Tek obje formatı dene
	var single struct {
		Firewall string `json:"firewall"`
		Detected bool   `json:"detected"`
	}
	if json.Unmarshal(data, &single) == nil && single.Detected {
		return single.Firewall
	}
	return ""
}

// ─── CMS Detection — whatweb ──────────────────────────────────────────────────

// runWhatWeb whatweb CLI aracını çalıştırarak CMS ve teknoloji tespiti yapar.
func runWhatWeb(targetURL string) (cms string, version string, techs []string) {
	// whatweb kurulu mu kontrol et
	if _, err := exec.LookPath("whatweb"); err != nil {
		// fmt.Printf("[DEBUG] whatweb not found for %s\n", targetURL)
		return "", "", nil // Araç yok, boş dön
	}

	tmp, err := os.CreateTemp("", "whatweb-*.json")
	if err != nil {
		logger.Debugf("whatweb temp dosya hatası: %v", err)
		return "", "", nil
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	ctxWW, cancelWW := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelWW()

	cmd := exec.CommandContext(ctxWW, "whatweb", "--no-errors", "--quiet",
		"--log-json="+tmp.Name(), targetURL)
	cmd.Run()

	data, err := os.ReadFile(tmp.Name())
	if err != nil || len(data) == 0 {
		return "", "", nil
	}

	// WhatWeb JSON: [{"target":"...","plugins":{"WordPress":{"version":["6.4"],...}}}]
	var results []struct {
		Plugins map[string]struct {
			Version []string `json:"version"`
		} `json:"plugins"`
	}
	if json.Unmarshal(data, &results) != nil || len(results) == 0 {
		return "", "", nil
	}

	plugins := results[0].Plugins

	// CMS öncelik sırası
	cmsList := []string{
		"WordPress", "Joomla", "Drupal", "Magento", "PrestaShop",
		"OpenCart", "TYPO3", "Shopify", "Ghost", "Wix",
		"Squarespace", "Laravel", "Django",
	}
	for _, c := range cmsList {
		if p, ok := plugins[c]; ok {
			cms = c
			if len(p.Version) > 0 {
				version = p.Version[0]
			}
			break
		}
	}

	// Tüm tespit edilen plugin adlarını techs olarak döndür
	for name := range plugins {
		techs = append(techs, name)
	}
	return cms, version, techs
}

// mergeTechs iki dilimi birleştirip tekilleştirir.
func mergeTechs(a, b []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(a)+len(b))
	for _, t := range append(a, b...) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// ─── Technology Stack Detection ──────────────────────────────────────────────

func detectTechnologies(resp *http.Response, html string) []string {
	var techs []string
	add := func(t string) { techs = append(techs, t) }
	has := func(s, sub string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(sub)) }

	server := resp.Header.Get("Server")
	powered := resp.Header.Get("X-Powered-By")
	ct := resp.Header.Get("Content-Type")

	// ── Web Servers ─────────────────────────────────────────────────────────
	if has(server, "apache") {
		add("Apache")
	}
	if has(server, "nginx") {
		add("Nginx")
	}
	if has(server, "iis") {
		add("IIS")
	}
	if has(server, "lighttpd") {
		add("Lighttpd")
	}
	if has(server, "caddy") {
		add("Caddy")
	}
	if has(server, "openresty") {
		add("OpenResty")
	}
	if has(server, "litespeed") {
		add("LiteSpeed")
	}
	if has(server, "gunicorn") {
		add("Gunicorn")
	}
	if has(server, "tomcat") {
		add("Tomcat")
	}
	if has(server, "jetty") {
		add("Jetty")
	}
	if has(server, "microsoft-httpapi") {
		add("Microsoft HTTPAPI")
	}

	// ── Languages / Platforms ────────────────────────────────────────────────
	if has(powered, "php") {
		// Versiyon dahil
		add("PHP" + extractVersion(powered, "php"))
	}
	if has(powered, "asp.net") {
		add("ASP.NET")
	}
	if has(powered, "express") {
		add("Express.js")
	}
	// Content-Type'dan dil ipucu
	if has(ct, "application/json") && resp.Header.Get("X-Powered-By") == "" {
		// JSON API
	}

	// ── CMS (passive only — CMS field zaten ayrı dolduruldu) ─────────────────
	if has(html, "wp-content") || has(html, "wp-includes") {
		add("WordPress")
	}
	if has(html, "joomla") {
		add("Joomla")
	}
	if has(html, "drupal") {
		add("Drupal")
	}
	if has(html, "shopify") {
		add("Shopify")
	}

	// ── JS Frameworks ────────────────────────────────────────────────────────
	if has(html, "react") || has(html, "__react") || has(html, "reactdom") {
		add("React")
	}
	if has(html, "vue.") || has(html, "__vue__") || has(html, "vue-router") {
		add("Vue.js")
	}
	if has(html, "ng-app") || has(html, "angular") || has(html, "ng-version") {
		add("Angular")
	}
	if has(html, "nuxt") {
		add("Nuxt.js")
	}
	if has(html, "__next/") || has(html, "_next/") {
		add("Next.js")
	}
	if has(html, "ember") {
		add("Ember.js")
	}
	if has(html, "backbone") {
		add("Backbone.js")
	}
	if has(html, "jquery") {
		add("jQuery")
	}
	if has(html, "bootstrap") {
		add("Bootstrap")
	}
	if has(html, "tailwind") {
		add("Tailwind CSS")
	}
	if has(html, "svelte") {
		add("Svelte")
	}

	// ── Analytics & Tracking ────────────────────────────────────────────────
	if has(html, "google-analytics") || has(html, "gtag(") || has(html, "ga('") {
		add("Google Analytics")
	}
	if has(html, "googletagmanager") {
		add("Google Tag Manager")
	}
	if has(html, "hotjar") {
		add("Hotjar")
	}
	if has(html, "segment.com") || has(html, "analytics.js") {
		add("Segment")
	}
	if has(html, "mixpanel") {
		add("Mixpanel")
	}
	if has(html, "facebook.net/en_US/fbevents") {
		add("Facebook Pixel")
	}
	if has(html, "clarity.ms") {
		add("Microsoft Clarity")
	}

	// ── CDN & Cloud ──────────────────────────────────────────────────────────
	if resp.Header.Get("CF-Ray") != "" {
		add("Cloudflare CDN")
	}
	if resp.Header.Get("X-Amz-Cf-Id") != "" {
		add("Amazon CloudFront")
	}
	if resp.Header.Get("X-Fastly-Request-Id") != "" {
		add("Fastly CDN")
	}
	if resp.Header.Get("X-Varnish") != "" {
		add("Varnish")
	}

	// ── Security Headers ─────────────────────────────────────────────────────
	if resp.Header.Get("Strict-Transport-Security") != "" {
		add("HSTS")
	}
	if resp.Header.Get("Content-Security-Policy") != "" {
		add("CSP")
	}

	// ── Database / Backend ipuçları ──────────────────────────────────────────
	if has(html, "mysql") || has(html, "mariadb") {
		add("MySQL/MariaDB (info leak)")
	}
	if has(html, "postgresql") {
		add("PostgreSQL (info leak)")
	}
	if has(html, "mongodb") {
		add("MongoDB (info leak)")
	}
	if has(html, "phpmyadmin") {
		add("phpMyAdmin")
	}

	// ── E-commerce ───────────────────────────────────────────────────────────
	if has(html, "woocommerce") {
		add("WooCommerce")
	}
	if has(html, "opencart") {
		add("OpenCart")
	}
	if has(html, "magento") {
		add("Magento")
	}
	if has(html, "prestashop") {
		add("PrestaShop")
	}

	// Deduplicate
	seen := make(map[string]bool)
	result := techs[:0]
	for _, t := range techs {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}

// extractVersion — "PHP/8.1.2" gibi string'den versiyon çeker.
func extractVersion(s, prefix string) string {
	low := strings.ToLower(s)
	idx := strings.Index(low, strings.ToLower(prefix))
	if idx == -1 {
		return ""
	}
	after := s[idx+len(prefix):]
	after = strings.TrimLeft(after, "/ ")
	end := strings.IndexAny(after, " \t\r\n;,\"'")
	if end < 0 {
		// Sonda delimiter yoksa tamamını al
		if len(after) > 0 {
			return " " + after
		}
		return ""
	}
	if end == 0 {
		return ""
	}
	return " " + after[:end]
}
