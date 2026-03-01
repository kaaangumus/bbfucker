package screenshot

import (
	"bufio"
	"bytes"
	"context"
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

type Capture struct {
	cfg     *config.Config
	verbose bool
	tool    string // "gowitness" or "aquatone"
}

type ScreenshotResult struct {
	URL        string
	OutputPath string
	Success    bool
	Error      string
}

func NewCapture(cfg *config.Config) *Capture {
	tool := cfg.Output.ScreenshotTool
	if tool == "" {
		tool = "gowitness" // Default
	}
	return &Capture{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
		tool:    tool,
	}
}

func (s *Capture) CheckInstalled() bool {
	_, err := exec.LookPath(s.tool)
	return err == nil
}

// CaptureURLs takes a list of URLs and captures screenshots
func (s *Capture) CaptureURLs(urls []string, outputDir string) []ScreenshotResult {
	if len(urls) == 0 {
		return nil
	}

	if !s.CheckInstalled() {
		if s.verbose {
			color.Yellow("[!] %s not installed, skipping screenshots", s.tool)
			color.Yellow("    Install: go install github.com/sensepost/gowitness@latest")
		}
		return nil
	}

	screenshotDir := filepath.Join(outputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		if s.verbose {
			color.Red("[!] Failed to create screenshot directory: %v", err)
		}
		return nil
	}

	if s.verbose {
		color.Cyan("[*] Capturing screenshots for %d URLs...", len(urls))
	}

	switch s.tool {
	case "gowitness":
		return s.captureWithGowitness(urls, screenshotDir)
	case "aquatone":
		return s.captureWithAquatone(urls, screenshotDir)
	default:
		if s.verbose {
			color.Yellow("[!] Unknown screenshot tool: %s", s.tool)
		}
		return nil
	}
}

// captureWithGowitness uses gowitness to capture screenshots
func (s *Capture) captureWithGowitness(urls []string, outputDir string) []ScreenshotResult {
	// Create temporary file with URLs
	tmpFile, err := os.CreateTemp("", "bbfucker_urls_*.txt")
	if err != nil {
		logger.Errorf("gowitness temp dosya oluşturulamadı: %v", err)
		return nil
	}
	defer os.Remove(tmpFile.Name())

	// Write URLs to file
	writer := bufio.NewWriter(tmpFile)
	for _, url := range urls {
		fmt.Fprintln(writer, url)
	}
	writer.Flush()
	tmpFile.Close()

	// Run gowitness
	args := []string{
		"file",
		"-f", tmpFile.Name(),
		"-P", outputDir,
		"--disable-logging",
		"--disable-db",
		"--screenshot-format", "png",
		"--timeout", "15",
	}

	if !s.verbose {
		args = append(args, "--no-http")
	}

	// gowitness timeout: 5 dakika
	ctxGW, cancelGW := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelGW()

	cmd := exec.CommandContext(ctxGW, "gowitness", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Warnf("gowitness hatası: %v", err)
		if s.verbose {
			if stderr.Len() > 0 {
				color.Yellow("    %s", strings.TrimSpace(stderr.String()))
			}
		}
		return nil
	}

	// Parse results
	results := make([]ScreenshotResult, 0)
	for _, url := range urls {
		// gowitness creates files like: http-example-com-80.png
		filename := s.urlToFilename(url) + ".png"
		fullPath := filepath.Join(outputDir, filename)
		
		success := false
		if _, err := os.Stat(fullPath); err == nil {
			success = true
		}

		results = append(results, ScreenshotResult{
			URL:        url,
			OutputPath: fullPath,
			Success:    success,
		})
	}

	if s.verbose {
		successCount := 0
		for _, r := range results {
			if r.Success {
				successCount++
			}
		}
		color.Green("[✓] Screenshots captured: %d/%d successful", successCount, len(urls))
	}

	return results
}

// captureWithAquatone uses aquatone to capture screenshots
func (s *Capture) captureWithAquatone(urls []string, outputDir string) []ScreenshotResult {
	// Create temporary file with URLs
	tmpFile, err := os.CreateTemp("", "bbfucker_urls_*.txt")
	if err != nil {
		logger.Errorf("aquatone temp dosya oluşturulamadı: %v", err)
		return nil
	}
	defer os.Remove(tmpFile.Name())

	// Write URLs to file
	writer := bufio.NewWriter(tmpFile)
	for _, url := range urls {
		fmt.Fprintln(writer, url)
	}
	writer.Flush()
	tmpFile.Close()

	// Run aquatone (5 dakika timeout)
	ctxAq, cancelAq := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelAq()

	cmd := exec.CommandContext(ctxAq, "aquatone", "-out", outputDir)
	stdinFile, err := os.Open(tmpFile.Name())
	if err != nil {
		if s.verbose {
			color.Yellow("[!] stdin dosyası açılamadı: %v", err)
		}
		return nil
	}
	cmd.Stdin = stdinFile
	defer stdinFile.Close()
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if s.verbose {
			color.Yellow("[!] aquatone error: %v", err)
		}
		return nil
	}

	// Aquatone creates screenshots in the output directory
	results := make([]ScreenshotResult, 0)
	for _, url := range urls {
		results = append(results, ScreenshotResult{
			URL:        url,
			OutputPath: filepath.Join(outputDir, "screenshots"),
			Success:    true, // Aquatone doesn't provide per-URL status easily
		})
	}

	if s.verbose {
		color.Green("[✓] Aquatone screenshots completed")
	}

	return results
}

// urlToFilename converts URL to safe filename (simplified)
func (s *Capture) urlToFilename(url string) string {
	// Remove protocol
	filename := strings.TrimPrefix(url, "https://")
	filename = strings.TrimPrefix(filename, "http://")
	
	// Replace unsafe characters
	filename = strings.ReplaceAll(filename, "/", "-")
	filename = strings.ReplaceAll(filename, ":", "-")
	filename = strings.ReplaceAll(filename, "?", "-")
	filename = strings.ReplaceAll(filename, "&", "-")
	filename = strings.ReplaceAll(filename, "=", "-")
	
	return filename
}
