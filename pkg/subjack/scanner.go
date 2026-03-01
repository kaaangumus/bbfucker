package subjack

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

type Scanner struct {
	cfg     *config.Config
	verbose bool
	client  *http.Client
}

type Takeover struct {
	Subdomain string
	Service   string
	CNAME     string
	Vulnerable bool
	Evidence  string
}

// Bilinen subdomain takeover fingerprints
var fingerprints = map[string][]string{
	"AWS/S3": {
		"NoSuchBucket",
		"The specified bucket does not exist",
	},
	"GitHub": {
		"There isn't a GitHub Pages site here",
		"For root URLs (like http://example.com/) you must provide an index.html file",
	},
	"Heroku": {
		"No such app",
		"herokucdn.com/error-pages/no-such-app.html",
	},
	"Shopify": {
		"Sorry, this shop is currently unavailable",
		"Only one step left!",
	},
	"Azure": {
		"404 Web Site not found",
		"azurewebsites.net",
	},
	"Bitbucket": {
		"Repository not found",
	},
	"Ghost": {
		"The thing you were looking for is no longer here",
	},
	"WordPress": {
		"Do you want to register",
	},
	"Cargo": {
		"If you're moving your domain away from Cargo",
	},
	"Tumblr": {
		"Whatever you were looking for doesn't currently exist at this address",
	},
	"Zendesk": {
		"Help Center Closed",
	},
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:     cfg,
		verbose: cfg.Output.Verbose,
		client: &http.Client{
			Timeout: time.Duration(cfg.Settings.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *Scanner) CheckTakeover(subdomains []string) []Takeover {
	if len(subdomains) == 0 {
		return nil
	}

	if s.verbose {
		color.Cyan("[*] Subjack takeover kontrolü (%d subdomain)...", len(subdomains))
	}

	var takeovers []Takeover
	var mu sync.Mutex
	var wg sync.WaitGroup

	// MaxWorkers/10 sıfır olabilir (deadlock) → minimum 1
	workerCount := s.cfg.Settings.MaxWorkers / 10
	if workerCount < 1 {
		workerCount = 1
	}

	// Sabit sayıda worker başlat (worker pool deseni)
	jobs := make(chan string, workerCount)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				if takeover := s.checkSingleSubdomain(sub); takeover != nil {
					logger.Infof("subdomain takeover bulundu: %s → %s", sub, takeover.Service)
					mu.Lock()
					takeovers = append(takeovers, *takeover)
					mu.Unlock()

					if s.verbose {
						fmt.Printf("[%s] TAKEOVER: %s → %s\n",
							color.RedString("CRITICAL"),
							sub,
							takeover.Service,
						)
					}
				}
			}
		}()
	}

	// İşleri kanala gönder
	for _, subdomain := range subdomains {
		jobs <- subdomain
	}
	close(jobs)

	wg.Wait()

	if s.verbose {
		if len(takeovers) > 0 {
			color.Red("[!] %d subdomain takeover riski bulundu!", len(takeovers))
		} else {
			color.Green("[✓] Takeover riski bulunamadı")
		}
	}

	return takeovers
}

func (s *Scanner) checkSingleSubdomain(subdomain string) *Takeover {
	// HTTP ve HTTPS dene
	for _, scheme := range []string{"http://", "https://"} {
		url := scheme + subdomain
		
		resp, err := s.client.Get(url)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Fingerprint'leri kontrol et
		for service, patterns := range fingerprints {
			for _, pattern := range patterns {
				if strings.Contains(bodyStr, pattern) {
					return &Takeover{
						Subdomain:  subdomain,
						Service:    service,
						Vulnerable: true,
						Evidence:   pattern,
					}
				}
			}
		}
	}

	return nil
}
