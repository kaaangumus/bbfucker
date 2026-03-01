package ffuf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

type Fuzzer struct {
	cfg     *config.Config
	verbose bool
}

type Finding struct {
	URL        string
	Host       string
	Path       string
	StatusCode int64
	Length     int64
	Words      int64
	Lines      int64
}

func NewFuzzer(cfg *config.Config) *Fuzzer {
	return &Fuzzer{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
	}
}

func (f *Fuzzer) CheckInstalled() bool {
	_, err := exec.LookPath("ffuf")
	return err == nil
}

func (f *Fuzzer) FuzzDirectories(ctx context.Context, baseURL string, wordlist []string) []Finding {
	if f.verbose {
		color.Cyan("[*] FFUF directory fuzzing: %s", baseURL)
	}

	var findings []Finding

	// Wordlist oluştur
	wordlistStr := ""
	if len(wordlist) == 0 {
		wordlist = []string{
			"admin", "login", "dashboard", "api", "v1", "v2",
			"backup", "config", "test", "dev", "staging",
			".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
		}
	}
	wordlistStr = strings.Join(wordlist, "\n")

	// ffuf threads: MaxWorkers/2 ama en az 10, en fazla 40
	ffufThreads := max(10, min(40, f.cfg.Settings.MaxWorkers/2))

	// ffuf binary'sini çalıştır
	args := []string{
		"-u", baseURL + "/FUZZ",
		"-w", "-", // stdin'den wordlist okuyacak
		"-t", fmt.Sprintf("%d", ffufThreads),
		"-timeout", fmt.Sprintf("%d", f.cfg.Settings.Timeout),
		"-ac", // auto-calibration
		"-json",
		"-s", // silent
	}

	cmd := exec.CommandContext(ctx, "ffuf", args...)
	cmd.Stdin = strings.NewReader(wordlistStr)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Warnf("ffuf çalıştırılamadı: %s - %v", baseURL, err)
		if f.verbose {
			color.Yellow("[!] FFUF çalıştırılamadı: %v", err)
		}
		return findings
	}

	// JSON output'u parse et
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			logger.Debugf("ffuf JSON parse hatası: %v", err)
			continue
		}

		if status, ok := result["status"].(float64); ok {
			var length, words, lines float64
			if v, ok := result["length"].(float64); ok {
				length = v
			}
			if v, ok := result["words"].(float64); ok {
				words = v
			}
			if v, ok := result["lines"].(float64); ok {
				lines = v
			}
			findings = append(findings, Finding{
				URL:        fmt.Sprintf("%v", result["url"]),
				Path:       fmt.Sprintf("%v", result["input"]),
				StatusCode: int64(status),
				Length:     int64(length),
				Words:      int64(words),
				Lines:      int64(lines),
			})
		}
	}

	if f.verbose && len(findings) > 0 {
		color.Green("[✓] FFUF: %d yol bulundu", len(findings))
	}

	return findings
}

func (f *Fuzzer) FuzzParameters(ctx context.Context, url string, params []string) []Finding {
	if f.verbose {
		color.Cyan("[*] FFUF parameter fuzzing: %s", url)
	}

	var findings []Finding

	// Parameter fuzzing implementation
	// params = ["id", "user", "page", "q", "search", "query", ...]

	if f.verbose && len(findings) > 0 {
		color.Green("[✓] FFUF: %d parametre bulundu", len(findings))
	}

	return findings
}
