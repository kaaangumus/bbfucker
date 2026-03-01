package gau

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

type Crawler struct {
	cfg     *config.Config
	verbose bool
}

func NewCrawler(cfg *config.Config) *Crawler {
	return &Crawler{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
	}
}

// CheckInstalled gau binary'sinin yüklü olup olmadığını kontrol eder
func (c *Crawler) CheckInstalled() bool {
	_, err := exec.LookPath("gau")
	return err == nil
}

func (c *Crawler) GetURLs(ctx context.Context, domain string) []string {
	if !c.CheckInstalled() {
		if c.verbose {
			color.Red("[✗] Gau binary bulunamadı - yüklemek için: go install github.com/lc/gau/v2/cmd/gau@latest")
		}
		return nil
	}

	if c.verbose {
		color.Cyan("[*] Gau URL gathering: %s", domain)
	}

	// MaxWorkers/10 sıfır olabilir, minimum 1
	gauThreads := c.cfg.Settings.MaxWorkers / 10
	if gauThreads < 1 {
		gauThreads = 1
	}

	// Gau komutunu çalıştır
	args := []string{
		"--threads", fmt.Sprintf("%d", gauThreads),
		"--timeout", fmt.Sprintf("%d", c.cfg.Settings.Timeout),
		"--providers", "wayback,commoncrawl,otx,urlscan",
		"--subs",  // Include subdomains
		domain,
	}

	if c.verbose {
		args = append(args, "--verbose")
	}

	cmd := exec.CommandContext(ctx, "gau", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		logger.Warnf("gau hatası: %s - %v", domain, err)
		if c.verbose {
			color.Yellow("[!] Gau hatası: %v", err)
		}
		return nil
	}

	// URL'leri parse et
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
			if c.verbose && len(urls) <= 10 {
				fmt.Printf("  [+] %s\n", url)
			}
		}
	}

	if c.verbose {
		if len(urls) > 10 {
			color.Yellow("  [*] ... ve %d URL daha", len(urls)-10)
		}
		color.Green("[✓] Gau: %d URL toplandı", len(urls))
	}

	return urls
}
