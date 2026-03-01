package phases

import (
	"bbfucker/pkg/config"
	"bbfucker/pkg/logger"
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Paket Sabitleri — Magic number'ları merkezi yönetim
// ============================================================================

const (
	// MaxBodyLimit — HTTP response body okuma limiti (OOM koruması)
	MaxBodyLimit = 10 * 1024 * 1024 // 10 MB
	// MediumBodyLimit — Orta boyutlu response'lar (API, JS dosyaları)
	MediumBodyLimit = 5 * 1024 * 1024 // 5 MB
	// SmallBodyLimit — Küçük response'lar (takeover kontrol, LFI/SQLi test)
	SmallBodyLimit = 1 * 1024 * 1024 // 1 MB
	// ScannerBufSize — bufio.Scanner buffer boyutu
	ScannerBufSize = 1024 * 1024 // 1 MB
	// DefaultHTTPTimeout — HTTP client varsayılan timeout
	DefaultHTTPTimeout = 30 * time.Second
	// ToolTimeout — Harici araç varsayılan timeout
	ToolTimeout = 5 * time.Minute
)

// ============================================================================
// Phase Interface - All phases must implement this
// ============================================================================

type Phase interface {
	// Name returns the phase name (e.g., "Phase 1: Passive Intelligence")
	Name() string
	
	// Description returns a brief description of what this phase does
	Description() string
	
	// Execute runs the phase with given context and configuration
	Execute(ctx context.Context, cfg *config.Config, input *PhaseInput) (*PhaseOutput, error)
	
	// IsEnabled checks if this phase is enabled in config
	IsEnabled(cfg *config.Config) bool
}

// ============================================================================
// Phase Input/Output Data Structures
// ============================================================================

// PhaseInput contains data passed to a phase from previous phases
type PhaseInput struct {
	Domain          string                 `json:"domain"`
	Subdomains      []string               `json:"subdomains,omitempty"`
	ResolvedDomains []string               `json:"resolved_domains,omitempty"`
	LiveHosts       []LiveHost             `json:"live_hosts,omitempty"`
	URLs            []string               `json:"urls,omitempty"`
	JSFiles         []string               `json:"js_files,omitempty"`
	Endpoints       []string               `json:"endpoints,omitempty"`
	Parameters      map[string][]string    `json:"parameters,omitempty"`
	Extra           map[string]interface{} `json:"extra,omitempty"`
}

// PhaseOutput contains results produced by a phase
type PhaseOutput struct {
	PhaseName       string                 `json:"phase_name"`
	Subdomains      []string               `json:"subdomains,omitempty"`
	ResolvedDomains []string               `json:"resolved_domains,omitempty"`
	LiveHosts       []LiveHost             `json:"live_hosts,omitempty"`
	URLs            []string               `json:"urls,omitempty"`
	JSFiles         []string               `json:"js_files,omitempty"`
	Endpoints       []string               `json:"endpoints,omitempty"`
	Parameters      map[string][]string    `json:"parameters,omitempty"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities,omitempty"`
	SensitiveFiles  []SensitiveFile        `json:"sensitive_files,omitempty"`
	OpenPorts       []PortInfo             `json:"open_ports,omitempty"`
	Services        []ServiceInfo          `json:"services,omitempty"`
	Findings        []Finding              `json:"findings,omitempty"`
	Statistics      Statistics             `json:"statistics"`
	Extra           map[string]interface{} `json:"extra,omitempty"`
}

// ============================================================================
// Common Data Structures
// ============================================================================

type LiveHost struct {
	URL           string   `json:"url"`
	Host          string   `json:"host,omitempty"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length,omitempty"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	WAF           string   `json:"waf,omitempty"`          // Detected WAF (Cloudflare, Akamai...)
	CMS           string   `json:"cms,omitempty"`          // Detected CMS (WordPress, Joomla...)
	CMSVersion    string   `json:"cms_version,omitempty"` // CMS version if detectable
}

type Vulnerability struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title,omitempty"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter,omitempty"`
	Payload     string `json:"payload,omitempty"`
	Description string `json:"description,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

type PortInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
}

type ServiceInfo struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Service string `json:"service"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

type SensitiveFile struct {
	URL     string `json:"url"`
	Type    string `json:"type"`     // backup, config, log, database, etc.
	Size    int    `json:"size"`
	Content string `json:"content"` // İlk 1000 karakter veya tam içerik
}

type Finding struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	URL         string                 `json:"url,omitempty"`
	Evidence    string                 `json:"evidence,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

type Statistics struct {
	TotalItems    int            `json:"total_items"`
	SuccessCount  int            `json:"success_count"`
	FailureCount  int            `json:"failure_count"`
	Duration      float64        `json:"duration_seconds"`
	ToolsUsed     []string       `json:"tools_used,omitempty"`
	Extra         map[string]int `json:"extra,omitempty"`
}

// ============================================================================
// Phase Executor - Orchestrates all phases
// ============================================================================

type PhaseExecutor struct {
	Config *config.Config
	Phases []Phase
}

func NewPhaseExecutor(cfg *config.Config) *PhaseExecutor {
	return &PhaseExecutor{
		Config: cfg,
		Phases: make([]Phase, 0),
	}
}

// RegisterPhase adds a phase to the execution pipeline
func (pe *PhaseExecutor) RegisterPhase(phase Phase) {
	pe.Phases = append(pe.Phases, phase)
}

// ExecuteAll runs all registered phases in sequence
func (pe *PhaseExecutor) ExecuteAll(ctx context.Context, domain string, outputDir string) (*PipelineResult, error) {
	result := &PipelineResult{
		Domain:       domain,
		Phases:       make([]*PhaseOutput, 0),
		PhaseOutputs: make([]*PhaseOutput, 0),
	}
	
	input := &PhaseInput{
		Domain: domain,
		Extra:  make(map[string]interface{}),
	}
	
	// Add outputDir to input.Extra
	if outputDir != "" {
		input.Extra["outputDir"] = outputDir
	}
	
	for _, phase := range pe.Phases {
		// Check if phase is enabled
		if !phase.IsEnabled(pe.Config) {
			logger.Debug("Phase devre dışı, atlanıyor", "phase", phase.Name())
			continue
		}
		
		phaseLog := logger.Default().With("phase", phase.Name())
		phaseLog.Info("Phase başlatılıyor")
		phaseStart := time.Now()
		
		// Execute phase
		output, err := phase.Execute(ctx, pe.Config, input)
		if err != nil {
			phaseLog.Error("Phase hatası", err)
			// Context iptal edildiyse (Ctrl+C) dur
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			// Aksi halde uyar ve devam et — bir fazın hata vermesi tüm taramayı öldürmemeli
			color.Red("\n[✗] %s hatası: %v — sonraki faza geçiliyor\n", phase.Name(), err)
			continue
		}
		
		phaseLog.Info("Phase tamamlandı",
			"süre", fmt.Sprintf("%.2fs", time.Since(phaseStart).Seconds()),
			"subdomain", fmt.Sprintf("%d", len(output.Subdomains)),
			"vuln", fmt.Sprintf("%d", len(output.Vulnerabilities)),
		)
		
		// Store phase output
		result.Phases = append(result.Phases, output)
		result.PhaseOutputs = append(result.PhaseOutputs, output)
		
		// Aggregate results
		result.LiveHosts = append(result.LiveHosts, output.LiveHosts...)
		result.SensitiveFiles = append(result.SensitiveFiles, output.SensitiveFiles...)
		result.OpenPorts = append(result.OpenPorts, output.OpenPorts...)
		result.Services = append(result.Services, output.Services...)
		result.JSFiles = mergeLists(result.JSFiles, output.JSFiles)
		result.Endpoints = mergeLists(result.Endpoints, output.Endpoints)
		
		// Aggregate parameters — hem key (baseURL) hem values (param names) düzgün aktar
		for baseURL, params := range output.Parameters {
			if result.Parameters == nil {
				result.Parameters = make(map[string][]string)
			}
			result.Parameters[baseURL] = append(result.Parameters[baseURL], params...)
		}
		
		// Prepare input for next phase (chain outputs)
		input = pe.mergeOutputToInput(input, output)
	}
	
	// Deduplicate aggregated results
	result.JSFiles = uniqueStrings(result.JSFiles)
	result.Endpoints = uniqueStrings(result.Endpoints)
	// Parameters map: her key altındaki param isimlerini tekilleştir
	for baseURL, params := range result.Parameters {
		result.Parameters[baseURL] = uniqueStrings(params)
	}
	
	return result, nil
}

// mergeOutputToInput chains phase outputs as inputs for next phases
func (pe *PhaseExecutor) mergeOutputToInput(input *PhaseInput, output *PhaseOutput) *PhaseInput {
	return &PhaseInput{
		Domain:          input.Domain,
		Subdomains:      mergeLists(input.Subdomains, output.Subdomains),
		ResolvedDomains: mergeLists(input.ResolvedDomains, output.ResolvedDomains),
		LiveHosts:       append(input.LiveHosts, output.LiveHosts...),
		URLs:            mergeLists(input.URLs, output.URLs),
		JSFiles:         mergeLists(input.JSFiles, output.JSFiles),
		Endpoints:       mergeLists(input.Endpoints, output.Endpoints),
		Parameters:      mergeParameters(input.Parameters, output.Parameters),
		Extra:           mergeExtra(input.Extra, output.Extra),
	}
}

// ============================================================================
// Pipeline Result
// ============================================================================

type PipelineResult struct {
	Domain string         `json:"domain"`
	Phases []*PhaseOutput `json:"phases"`
	
	// Aggregated results (for quick access)
	LiveHosts      []LiveHost      `json:"live_hosts,omitempty"`
	SensitiveFiles []SensitiveFile `json:"sensitive_files,omitempty"`
	OpenPorts      []PortInfo      `json:"open_ports,omitempty"`
	Services       []ServiceInfo   `json:"services,omitempty"`
	JSFiles        []string               `json:"js_files,omitempty"`
	Endpoints      []string               `json:"endpoints,omitempty"`
	Parameters     map[string][]string    `json:"parameters,omitempty"`
	PhaseOutputs   []*PhaseOutput         `json:"-"` // For backward compatibility
}

// GetAllSubdomains aggregates subdomains from all phases
func (pr *PipelineResult) GetAllSubdomains() []string {
	uniqueMap := make(map[string]bool)
	for _, phase := range pr.Phases {
		for _, sub := range phase.Subdomains {
			uniqueMap[sub] = true
		}
	}
	
	result := make([]string, 0, len(uniqueMap))
	for sub := range uniqueMap {
		result = append(result, sub)
	}
	return result
}

// GetAllURLs aggregates URLs from all phases
func (pr *PipelineResult) GetAllURLs() []string {
	uniqueMap := make(map[string]bool)
	for _, phase := range pr.Phases {
		for _, url := range phase.URLs {
			uniqueMap[url] = true
		}
	}
	
	result := make([]string, 0, len(uniqueMap))
	for url := range uniqueMap {
		result = append(result, url)
	}
	return result
}

// GetAllVulnerabilities aggregates vulnerabilities from all phases
func (pr *PipelineResult) GetAllVulnerabilities() []Vulnerability {
	var result []Vulnerability
	for _, phase := range pr.Phases {
		result = append(result, phase.Vulnerabilities...)
	}
	return result
}

// GetAllSensitiveFiles aggregates sensitive files from all phases
func (pr *PipelineResult) GetAllSensitiveFiles() []SensitiveFile {
	var result []SensitiveFile
	for _, phase := range pr.Phases {
		result = append(result, phase.SensitiveFiles...)
	}
	return result
}

// ============================================================================
// Helper Functions
// ============================================================================

func mergeLists(list1, list2 []string) []string {
	uniqueMap := make(map[string]bool)
	for _, item := range list1 {
		uniqueMap[item] = true
	}
	for _, item := range list2 {
		uniqueMap[item] = true
	}
	
	result := make([]string, 0, len(uniqueMap))
	for item := range uniqueMap {
		result = append(result, item)
	}
	return result
}

func mergeParameters(map1, map2 map[string][]string) map[string][]string {
	result := make(map[string][]string)
	
	for k, v := range map1 {
		result[k] = v
	}
	
	for k, v := range map2 {
		if existing, ok := result[k]; ok {
			result[k] = mergeLists(existing, v)
		} else {
			result[k] = v
		}
	}
	
	return result
}

func mergeExtra(map1, map2 map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	
	for k, v := range map1 {
		result[k] = v
	}
	
	for k, v := range map2 {
		result[k] = v
	}
	
	return result
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, item := range input {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
