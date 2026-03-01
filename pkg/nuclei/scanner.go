package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

type Scanner struct {
	cfg     *config.Config
	verbose bool
}

type Finding struct {
	TemplateID   string
	TemplateName string
	Host         string
	MatchedAt    string
	Severity     string
	Description  string
	CWE          string
	CVE          string
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
	}
}

func (s *Scanner) CheckInstalled() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

func (s *Scanner) ScanTargets(ctx context.Context, targets []string) []Finding {
	return s.runNuclei(ctx, targets, []string{"cve", "misconfig", "exposed-panel", "tech", "vuln"}, false)
}

// ScanTargetsWithTags - Nuclei taraması yapar (özel tag'lerle)
func (s *Scanner) ScanTargetsWithTags(ctx context.Context, targets []string, tags []string) []Finding {
	return s.runNuclei(ctx, targets, tags, false)
}

// ScanTargetsStealth WAF korumalı hedefler için düşük hızda nuclei taraması yapar.
// Concurrency 3, rate-limit 15 req/sn olarak ayarlanır.
func (s *Scanner) ScanTargetsStealth(ctx context.Context, targets []string) []Finding {
	if s.verbose {
		color.Yellow("[!] Nuclei stealth modu: WAF tespit edildi — yavaşlatılmış tarama (%d hedef)", len(targets))
	}
	return s.runNuclei(ctx, targets, []string{"cve", "misconfig", "exposed-panel", "tech", "vuln"}, true)
}

// runNuclei — ortak nuclei çalıştırma ve parse mantığı.
// stealth=true iken düşük concurrency + rate limiting uygulanır.
func (s *Scanner) runNuclei(ctx context.Context, targets []string, tags []string, stealth bool) []Finding {
	if len(targets) == 0 {
		return nil
	}

	// Pipeline ctx iptal edilmiş olsa bile (ör: önceki araç Ctrl+C ile durduruldu)
	// nuclei kendi bağımsız context'i ile çalışır.
	// Timeout: hedef başına 20s, normal max 30dk, stealth max 60dk.
	nucleiTimeout := time.Duration(len(targets)) * 20 * time.Second
	maxTimeout := 30 * time.Minute
	if stealth {
		nucleiTimeout = time.Duration(len(targets)) * 40 * time.Second
		maxTimeout = 60 * time.Minute
	}
	if nucleiTimeout > maxTimeout {
		nucleiTimeout = maxTimeout
	}
	nucleiCtx, nucleiCancel := context.WithTimeout(context.Background(), nucleiTimeout)
	defer nucleiCancel()

	if s.verbose {
		mode := "normal"
		if stealth {
			mode = "stealth"
		}
		color.Cyan("[*] Nuclei taraması başlatılıyor (%d hedef, tags=%v, mod=%s, timeout=%s)...", len(targets), tags, mode, nucleiTimeout.Round(time.Second))
	}

	// Hedefleri temp dosyaya yaz (stdin yerine — daha güvenilir)
	tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		logger.Warnf("nuclei temp dosyası oluşturulamadı: %v", err)
		return nil
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	var findings []Finding

	concurrency := max(1, s.cfg.Settings.MaxWorkers/2)
	if stealth {
		concurrency = 3
	}

	args := []string{
		"-l", tmpFile.Name(),
		"-severity", "critical,high,medium",
		"-tags", strings.Join(tags, ","),
		"-c", fmt.Sprintf("%d", concurrency),
		"-timeout", fmt.Sprintf("%d", s.cfg.Settings.Timeout),
		"-jsonl",
		"-silent",
		"-no-interactsh",
	}

	if stealth {
		args = append(args, "-rate-limit", "15")
	}

	cmd := exec.CommandContext(nucleiCtx, "nuclei", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Warnf("nuclei çalıştırılamadı: %v (targets=%d, tags=%v)", err, len(targets), tags)
		if s.verbose {
			color.Yellow("[!] Nuclei çalıştırılamadı: %v", err)
		}
		return findings
	}

	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			logger.Debugf("nuclei JSON parse hatası: %v", err)
			continue
		}

		info, ok := result["info"].(map[string]interface{})
		if !ok {
			continue
		}
		finding := Finding{
			TemplateID:   fmt.Sprintf("%v", result["template-id"]),
			TemplateName: fmt.Sprintf("%v", info["name"]),
			Host:         fmt.Sprintf("%v", result["host"]),
			MatchedAt:    fmt.Sprintf("%v", result["matched-at"]),
			Severity:     fmt.Sprintf("%v", info["severity"]),
			Description:  fmt.Sprintf("%v", info["description"]),
		}

		if classification, ok := info["classification"].(map[string]interface{}); ok {
			if cveId, ok := classification["cve-id"].([]interface{}); ok && len(cveId) > 0 {
				finding.CVE = fmt.Sprintf("%v", cveId[0])
			}
			if cweId, ok := classification["cwe-id"].([]interface{}); ok && len(cweId) > 0 {
				finding.CWE = fmt.Sprintf("CWE-%v", cweId[0])
			}
		}

		findings = append(findings, finding)

		if s.verbose {
			severityColor := color.YellowString
			if finding.Severity == "critical" || finding.Severity == "high" {
				severityColor = color.RedString
			}
			fmt.Printf("[%s] %s - %s\n",
				severityColor(finding.Severity),
				finding.TemplateID,
				finding.Host,
			)
		}
	}

	if s.verbose {
		color.Green("[✓] Nuclei: %d bulgu", len(findings))
	}

	return findings
}

func (s *Scanner) EnsureTemplates() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	templatesPath := filepath.Join(homeDir, "nuclei-templates")

	// Template'ler yoksa indir — nuclei v3: "-ut" flag'i
	if _, err := os.Stat(templatesPath); os.IsNotExist(err) {
		if s.verbose {
			color.Cyan("[*] Nuclei template'leri indiriliyor (ilk seferlik)...")
		}
		// nuclei v3: -ut (eski: -update-templates)
		cmd := exec.Command("nuclei", "-ut", "-silent")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			// Hata olsa bile devam et — nuclei taramada otomatik indirir
			if s.verbose {
				color.Yellow("[!] Template indirme hatası: %v — nuclei taramada otomatik indirmeye çalışacak", err)
			}
		} else if s.verbose {
				color.Green("[✓] Nuclei template'leri indirildi")
		}
		return nil
	}

	if s.verbose {
		color.Green("[✓] Nuclei template'leri mevcut")
	}
	return nil
}
