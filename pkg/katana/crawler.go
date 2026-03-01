package katana

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

func (c *Crawler) CheckInstalled() bool {
	_, err := exec.LookPath("katana")
	return err == nil
}

func (c *Crawler) CrawlURL(ctx context.Context, url string) []string {
	if c.verbose {
		color.Cyan("[*] Katana crawler başlatılıyor: %s", url)
	}

	// MaxWorkers/10 sıfır olabilir, minimum 1
	katanaConc := c.cfg.Settings.MaxWorkers / 10
	if katanaConc < 1 {
		katanaConc = 1
	}

	var urls []string

	// katana binary'sini çalıştır
	args := []string{
		"-u", url,
		"-d", "3", // depth
		"-c", fmt.Sprintf("%d", katanaConc),
		"-timeout", fmt.Sprintf("%d", c.cfg.Settings.Timeout),
		"-jc", // all crawling
		"-silent",
	}

	cmd := exec.CommandContext(ctx, "katana", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Warnf("katana çalıştırılamadı: %s - %v", url, err)
		if c.verbose {
			color.Yellow("[!] Katana çalıştırılamadı: %v", err)
		}
		return urls
	}

	// Her satır bir URL
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			urls = append(urls, line)
		}
	}

	if c.verbose {
		color.Green("[✓] Katana: %d URL bulundu", len(urls))
	}

	return urls
}

func (c *Crawler) CrawlMultiple(ctx context.Context, targets []string) []string {
	var allURLs []string
	
	for _, target := range targets {
		urls := c.CrawlURL(ctx, target)
		allURLs = append(allURLs, urls...)
	}

	// Duplicate'leri temizle
	uniqueURLs := make(map[string]bool)
	var result []string
	for _, url := range allURLs {
		if !uniqueURLs[url] {
			uniqueURLs[url] = true
			result = append(result, url)
		}
	}

	return result
}
