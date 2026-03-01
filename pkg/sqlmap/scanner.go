package sqlmap

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

// SQLMapScanner SQLMap wrapper
type SQLMapScanner struct {
	level     int
	risk      int
	threads   int
	technique string
	verbose   bool
	outputDir string
}

// NewSQLMapScanner yeni SQLMap scanner oluşturur
func NewSQLMapScanner(level, risk, threads int, technique string, outputDir string, verbose bool) *SQLMapScanner {
	return &SQLMapScanner{
		level:     level,
		risk:      risk,
		threads:   threads,
		technique: technique,
		verbose:   verbose,
		outputDir: outputDir,
	}
}

// SQLiResult SQLi tarama sonucu
type SQLiResult struct {
	URL           string
	Parameter     string
	Vulnerable    bool
	InjectionType string
	DBMS          string
	Payload       string
	Data          string
}

// CheckInstalled SQLMap'in kurulu olup olmadığını kontrol eder
func CheckInstalled() error {
	cmd := exec.Command("sqlmap", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sqlmap bulunamadı. Kurulum: apt install sqlmap veya git clone https://github.com/sqlmapproject/sqlmap.git")
	}
	return nil
}

// ScanURLs URL listesini SQLMap ile tarar
func (s *SQLMapScanner) ScanURLs(ctx context.Context, urls []string) ([]SQLiResult, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("URL listesi boş")
	}

	if err := CheckInstalled(); err != nil {
		logger.Error("sqlmap kurulu değil", err)
		return nil, err
	}

	if s.verbose {
		color.Cyan("[*] SQLMap ile %d URL taranıyor (level=%d, risk=%d)...", len(urls), s.level, s.risk)
	}

	// URL listesini dosyaya yaz
	urlsFile := filepath.Join(s.outputDir, "sqli_targets.txt")
	if err := s.writeURLsToFile(urls, urlsFile); err != nil {
		logger.Errorf("URL dosyası yazılamadı: %v", err)
		return nil, fmt.Errorf("URL dosyası yazılamadı: %w", err)
	}

	var results []SQLiResult

	// Her URL'i tara
	for i, url := range urls {
		if s.verbose {
			color.Yellow("[%d/%d] Taranıyor: %s", i+1, len(urls), url)
		}

		result, err := s.scanSingleURL(ctx, url)
		if err != nil {
			logger.Warnf("sqlmap tarama hatası: %s - %v", url, err)
			if s.verbose {
				color.Red("[!] Hata: %v", err)
			}
			continue
		}

		if result.Vulnerable {
			results = append(results, result)
			color.Green("[✓] SQLi bulundu: %s (param: %s)", url, result.Parameter)
		}
	}

	if s.verbose {
		color.Cyan("[*] SQLMap taraması tamamlandı: %d vulnerable", len(results))
	}

	return results, nil
}

// scanSingleURL tek bir URL'i tarar
func (s *SQLMapScanner) scanSingleURL(ctx context.Context, url string) (SQLiResult, error) {
	result := SQLiResult{
		URL:        url,
		Vulnerable: false,
	}

	// SQLMap output dizini
	scanOutputDir := filepath.Join(s.outputDir, "sqlmap_scans")
	os.MkdirAll(scanOutputDir, 0755)

	// SQLMap komutu
	args := []string{
		"-u", url,
		"--batch",                    // Non-interactive
		"--random-agent",             // Random user agent
		"--level", fmt.Sprintf("%d", s.level),
		"--risk", fmt.Sprintf("%d", s.risk),
		"--threads", fmt.Sprintf("%d", s.threads),
		"--technique", s.technique,
		"--output-dir", scanOutputDir,
		"--flush-session",            // Fresh scan
		"--fresh-queries",
	}

	// Timeout context (her URL için max 5 dakika, parent context'e bağlı)
	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, "sqlmap", args...)
	
	// Output yakalama
	output, err := cmd.CombinedOutput()
	if err != nil {
		// SQLMap return code'u 0 değil ise de vulnerable bulabilir
		if ctx.Err() == context.DeadlineExceeded {
			return result, fmt.Errorf("timeout")
		}
		// Output'ta vulnerable var mı kontrol et
		if !strings.Contains(string(output), "vulnerable") {
			return result, fmt.Errorf("sqlmap error: %w", err)
		}
	}

	// Output'u parse et
	s.parseOutput(string(output), &result)

	return result, nil
}

// parseOutput SQLMap output'unu parse eder
func (s *SQLMapScanner) parseOutput(output string, result *SQLiResult) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Vulnerable tespit
		if strings.Contains(line, "Parameter:") && strings.Contains(line, "is vulnerable") {
			result.Vulnerable = true
			// Parameter ismini çıkar
			if parts := strings.Split(line, "Parameter:"); len(parts) > 1 {
				paramPart := strings.TrimSpace(parts[1])
				if idx := strings.Index(paramPart, " "); idx > 0 {
					result.Parameter = paramPart[:idx]
				}
			}
		}

		// Injection type
		if strings.Contains(line, "Type:") {
			if parts := strings.Split(line, "Type:"); len(parts) > 1 {
				result.InjectionType = strings.TrimSpace(parts[1])
			}
		}

		// DBMS detection
		if strings.Contains(line, "back-end DBMS:") {
			if parts := strings.Split(line, "back-end DBMS:"); len(parts) > 1 {
				result.DBMS = strings.TrimSpace(parts[1])
			}
		}

		// Payload
		if strings.Contains(line, "Payload:") {
			if parts := strings.Split(line, "Payload:"); len(parts) > 1 {
				result.Payload = strings.TrimSpace(parts[1])
			}
		}
	}

	// Full output'u kaydet
	result.Data = output
}

// ScanFromFile dosyadan URL okuyup tarar
func (s *SQLMapScanner) ScanFromFile(ctx context.Context, filePath string) ([]SQLiResult, error) {
	urls, err := s.readURLsFromFile(filePath)
	if err != nil {
		return nil, err
	}

	return s.ScanURLs(ctx, urls)
}

// readURLsFromFile dosyadan URL'leri okur
func (s *SQLMapScanner) readURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" && !strings.HasPrefix(url, "#") {
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// writeURLsToFile URL'leri dosyaya yazar
func (s *SQLMapScanner) writeURLsToFile(urls []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, url := range urls {
		fmt.Fprintln(writer, url)
	}

	return writer.Flush()
}

// SaveResults sonuçları dosyaya kaydeder
func (s *SQLMapScanner) SaveResults(results []SQLiResult, outputPath string) error {
	if len(results) == 0 {
		return nil
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	
	fmt.Fprintln(writer, "# SQLMap Scan Results")
	fmt.Fprintln(writer, "# Generated:", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(writer, "")

	for i, result := range results {
		fmt.Fprintf(writer, "[%d] URL: %s\n", i+1, result.URL)
		fmt.Fprintf(writer, "    Parameter: %s\n", result.Parameter)
		fmt.Fprintf(writer, "    Vulnerable: %v\n", result.Vulnerable)
		fmt.Fprintf(writer, "    Injection Type: %s\n", result.InjectionType)
		fmt.Fprintf(writer, "    DBMS: %s\n", result.DBMS)
		fmt.Fprintf(writer, "    Payload: %s\n", result.Payload)
		fmt.Fprintln(writer, "")
	}

	return writer.Flush()
}

// QuickScan hızlı tarama (level=1, risk=1)
func QuickScan(ctx context.Context, urls []string, outputDir string, verbose bool) ([]SQLiResult, error) {
	scanner := NewSQLMapScanner(1, 1, 10, "BEUSTQ", outputDir, verbose)
	return scanner.ScanURLs(ctx, urls)
}

// DeepScan derin tarama (level=5, risk=3)
func DeepScan(ctx context.Context, urls []string, outputDir string, verbose bool) ([]SQLiResult, error) {
	scanner := NewSQLMapScanner(5, 3, 10, "BEUSTQ", outputDir, verbose)
	return scanner.ScanURLs(ctx, urls)
}
