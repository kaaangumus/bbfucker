package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

type Scanner struct {
	cfg     *config.Config
	verbose bool
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
	}
}

func (s *Scanner) CheckInstalled() bool {
	_, err := exec.LookPath("subfinder")
	return err == nil
}

func (s *Scanner) FindSubdomains(ctx context.Context, domain string) []string {
	if s.verbose {
		color.Cyan("[*] Subfinder çalıştırılıyor (50+ kaynak)...")
	}

	var subdomains []string

	// subfinder binary'sini çalıştır
	args := []string{
		"-d", domain,
		"-all", // tüm kaynaklar
		"-t", fmt.Sprintf("%d", s.cfg.Settings.MaxWorkers),
		"-timeout", fmt.Sprintf("%d", s.cfg.Settings.Timeout),
		"-silent",
	}

	cmd := exec.CommandContext(ctx, "subfinder", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Warnf("subfinder çalıştırılamadı: %s - %v", domain, err)
		if s.verbose {
			color.Yellow("[!] Subfinder çalıştırılamadı: %v", err)
		}
		return subdomains
	}

	// Her satır bir subdomain
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			subdomains = append(subdomains, line)
			if s.verbose && len(subdomains) <= 10 {
				fmt.Printf("[+] %s\n", line)
			}
		}
	}

	if s.verbose {
		if len(subdomains) > 10 {
			color.Yellow("[*] ... ve %d subdomain daha", len(subdomains)-10)
		}
		color.Green("[✓] Subfinder: %d subdomain bulundu", len(subdomains))
	}

	return subdomains
}
