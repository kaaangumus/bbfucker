package dalfox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
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

type XSSFinding struct {
	URL       string
	Parameter string
	Payload   string
	Evidence  string
	Severity  string
	POC       string
}

type dalfoxOutput struct {
	Type      string `json:"type"`
	Data      string `json:"data"`
	PoC       string `json:"poc"`
	Param     string `json:"param"`
	Payload   string `json:"payload"`
	Evidence  string `json:"evidence"`
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
	}
}

// CheckInstalled dalfox binary'sinin yüklü olup olmadığını kontrol eder
func (s *Scanner) CheckInstalled() bool {
	_, err := exec.LookPath("dalfox")
	return err == nil
}

func (s *Scanner) ScanURL(ctx context.Context, targetURL string) []XSSFinding {
	if !s.CheckInstalled() {
		if s.verbose {
			color.Red("[✗] Dalfox binary bulunamadı - yüklemek için: go install github.com/hahwul/dalfox/v2@latest")
		}
		return nil
	}

	if s.verbose {
		color.Cyan("[*] Dalfox XSS taraması: %s", targetURL)
	}

	args := []string{
		"url", targetURL,
		"--silence",
		"--format", "json",
		"--skip-bav",  // BAV (Blind XSS) atla - daha hızlı
	}

	if s.cfg.Phase6ParameterFuzzing.XSSTesting.Dalfox.Mining {
		args = append(args, "--mining-dict", "true")
	}

	if s.cfg.Phase6ParameterFuzzing.XSSTesting.Dalfox.WAFEvasion {
		args = append(args, "--waf-evasion")
	}

	cmd := exec.CommandContext(ctx, "dalfox", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		logger.Warnf("dalfox tarama hatası: %s - %v", targetURL, err)
		if s.verbose {
			color.Yellow("[!] Dalfox tarama hatası: %v", err)
		}
		return nil
	}

	return s.parseOutput(stdout.String())
}

func (s *Scanner) ScanMultiple(ctx context.Context, urls []string) []XSSFinding {
	if !s.CheckInstalled() {
		if s.verbose {
			color.Yellow("[!] Dalfox kurulu değil - atlanıyor")
		}
		return nil
	}

	var allFindings []XSSFinding

	if s.verbose {
		color.Cyan("[*] Dalfox: %d URL taranıyor...", len(urls))
	}

	for i, url := range urls {
		findings := s.ScanURL(ctx, url)
		allFindings = append(allFindings, findings...)

		if s.verbose && (i+1)%5 == 0 {
			fmt.Printf("  [%d/%d] tarandı...\n", i+1, len(urls))
		}
	}

	if s.verbose && len(allFindings) > 0 {
		color.Green("[✓] Dalfox: %d XSS açığı bulundu", len(allFindings))
	}

	return allFindings
}

// ScanURLStealth WAF korumalı hedefe WAF evasion + gecikme ile XSS taraması yapar.
// wafDelay request arası bekleme süresidir (örn: 2500ms).
func (s *Scanner) ScanURLStealth(ctx context.Context, targetURL string, wafDelay time.Duration) []XSSFinding {
	if !s.CheckInstalled() {
		return nil
	}

	if s.verbose {
		color.Yellow("  [!] Dalfox stealth: WAF evasion aktif (%s) — %s", wafDelay, targetURL)
	}

	args := []string{
		"url", targetURL,
		"--silence",
		"--format", "json",
		"--skip-bav",
		"--waf-evasion", // WAF tespit edildiğinde her zaman aktif
		"--delay", fmt.Sprintf("%d", wafDelay.Milliseconds()),
	}

	if s.cfg.Phase6ParameterFuzzing.XSSTesting.Dalfox.Mining {
		args = append(args, "--mining-dict", "true")
	}

	cmd := exec.CommandContext(ctx, "dalfox", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		logger.Warnf("dalfox stealth tarama hatası: %s - %v", targetURL, err)
		return nil
	}

	return s.parseOutput(stdout.String())
}

// ScanMultipleStealth WAF korumalı URL listesini stealth modda tarar.
// requestDelay her URL arasında bekleme süresidir.
func (s *Scanner) ScanMultipleStealth(ctx context.Context, urls []string, requestDelay time.Duration) []XSSFinding {
	if !s.CheckInstalled() {
		if s.verbose {
			color.Yellow("[!] Dalfox kurulu değil - atlanıyor")
		}
		return nil
	}

	var allFindings []XSSFinding

	if s.verbose {
		color.Yellow("[!] Dalfox stealth modu: WAF tespit edildi — %d URL, gecikme %s", len(urls), requestDelay)
	}

	for i, url := range urls {
		// Her URL'den önce bekleme (WAF rate limit'i aşmamak için)
		if i > 0 && requestDelay > 0 {
			select {
			case <-ctx.Done():
				return allFindings
			case <-time.After(requestDelay):
			}
		}

		findings := s.ScanURLStealth(ctx, url, requestDelay)
		allFindings = append(allFindings, findings...)

		if s.verbose && (i+1)%5 == 0 {
			fmt.Printf("  [%d/%d] tarandı...\n", i+1, len(urls))
		}
	}

	if s.verbose && len(allFindings) > 0 {
		color.Green("[✓] Dalfox stealth: %d XSS açığı bulundu", len(allFindings))
	}

	return allFindings
}

func (s *Scanner) parseOutput(output string) []XSSFinding {
	var findings []XSSFinding

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result dalfoxOutput
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			logger.Debugf("dalfox JSON parse hatası: %v", err)
			continue
		}

		// Sadece vulnerability sonuçlarını al
		if result.Type == "V" || result.Type == "POC" {
			finding := XSSFinding{
				URL:       result.Data,
				Parameter: result.Param,
				Payload:   result.Payload,
				Evidence:  result.Evidence,
				Severity:  "High",
				POC:       result.PoC,
			}
			findings = append(findings, finding)

			if s.verbose {
				fmt.Printf("[%s] XSS: %s @ %s\n",
					color.RedString("HIGH"),
					result.Param,
					truncateURL(result.Data, 60))
			}
		}
	}

	return findings
}

func truncateURL(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
