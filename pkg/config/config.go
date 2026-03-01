package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// Main Config Struct - 6-Phase Professional Pipeline
// ============================================================================

type Config struct {
	Settings            Settings            `yaml:"settings"`
	Phase1Passive       Phase1Passive       `yaml:"phase1_passive"`
	Phase2DNS           Phase2DNS           `yaml:"phase2_dns"`
	Phase3Infrastructure Phase3Infrastructure `yaml:"phase3_infrastructure"`
	Phase4WebProbing    Phase4WebProbing    `yaml:"phase4_web_probing"`
	Phase5ContentAnalysis Phase5ContentAnalysis `yaml:"phase5_content_analysis"`
	Phase6ParameterFuzzing Phase6ParameterFuzzing `yaml:"phase6_parameter_fuzzing"`
	Wordlists           Wordlists           `yaml:"wordlists"`
	Resolvers           Resolvers           `yaml:"resolvers"`
	VulnerabilityChecks VulnerabilityChecks `yaml:"vulnerability_checks"`
	Output              Output              `yaml:"output"`
}

// ============================================================================
// Global Settings
// ============================================================================

type Settings struct {
	MaxWorkers         int    `yaml:"max_workers"`
	Timeout            int    `yaml:"timeout"`
	RetryAttempts      int    `yaml:"retry_attempts"`
	DeepScan           bool   `yaml:"deep_scan"`
	UserAgent          string `yaml:"user_agent"`
	Resolvers          string `yaml:"resolvers"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"` // nil = default true (bug bounty uyumlu)
}

// ============================================================================
// Phase 1: Passive Intelligence & Scope Mapping
// ============================================================================

type Phase1Passive struct {
	Enabled        bool           `yaml:"enabled"`
	ASNDiscovery   ASNDiscovery   `yaml:"asn_discovery"`
	SubdomainEnum  SubdomainEnum  `yaml:"subdomain_enum"`
}

type ASNDiscovery struct {
	Enabled      bool         `yaml:"enabled"`
	Tools        []string     `yaml:"tools"`
	APIProviders APIProviders `yaml:"api_providers"`
}

type APIProviders struct {
	URLScan    APIProvider `yaml:"urlscan"`
	VirusTotal APIProvider `yaml:"virustotal"`
	C99        APIProvider `yaml:"c99"`
}

type APIProvider struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key,omitempty"`
	APIURL  string `yaml:"api_url,omitempty"`
	ScanURL string `yaml:"scan_url,omitempty"`
}

type SubdomainEnum struct {
	Enabled bool              `yaml:"enabled"`
	Tools   SubdomainTools    `yaml:"tools"`
	Sources SubdomainSources  `yaml:"sources"`
}

type SubdomainTools struct {
	Subfinder       SubfinderConfig       `yaml:"subfinder"`
	Amass           AmassConfig           `yaml:"amass"`
	Findomain       BasicToolConfig       `yaml:"findomain"`
	Assetfinder     AssetfinderConfig     `yaml:"assetfinder"`
	Chaos           BasicToolConfig       `yaml:"chaos"`
	GithubSubdomain BasicToolConfig       `yaml:"github_subdomain"`
	Subdog          BasicToolConfig       `yaml:"subdog"`
	TLDFinder       BasicToolConfig       `yaml:"tldfinder"`
	BBOT            BBOTConfig            `yaml:"bbot"`
	OneForAll       OneForAllConfig       `yaml:"oneforall"`
}

type SubfinderConfig struct {
	Enabled    bool `yaml:"enabled"`
	AllSources bool `yaml:"all_sources"`
	Recursive  bool `yaml:"recursive"`
}

type AmassConfig struct {
	Enabled      bool `yaml:"enabled"`
	Passive      bool `yaml:"passive"`
	NoRecursive  bool `yaml:"no_recursive"`
	NoAlts       bool `yaml:"no_alts"`
}

type AssetfinderConfig struct {
	Enabled  bool `yaml:"enabled"`
	SubsOnly bool `yaml:"subs_only"`
}

type BBOTConfig struct {
	Enabled bool   `yaml:"enabled"`
	Flags   string `yaml:"flags"`
}

type OneForAllConfig struct {
	Enabled bool `yaml:"enabled"`
	NoBrute bool `yaml:"no_brute"`
}

type BasicToolConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SubdomainSources struct {
	Crtsh          CrtshSource          `yaml:"crtsh"`
	SecurityTrails SecurityTrailsSource `yaml:"securitytrails"`
	HackerTarget   bool                 `yaml:"hackertarget"`
	ThreatCrowd    bool                 `yaml:"threatcrowd"`
	AlienVault     bool                 `yaml:"alienvault"`
	Wayback        bool                 `yaml:"wayback"`
	VirusTotal     bool                 `yaml:"virustotal"`
	URLScan        bool                 `yaml:"urlscan"`
}

type CrtshSource struct {
	Enabled bool   `yaml:"enabled"`
	APIURL  string `yaml:"api_url"`
}

type SecurityTrailsSource struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
	APIURL  string `yaml:"api_url"`
}

// ============================================================================
// Phase 2: DNS Resolution & Brute-forcing
// ============================================================================

type Phase2DNS struct {
	Enabled      bool         `yaml:"enabled"`
	Filtering    Filtering    `yaml:"filtering"`
	Resolution   Resolution   `yaml:"resolution"`
	Bruteforce   Bruteforce   `yaml:"bruteforce"`
	Permutations Permutations `yaml:"permutations"`
}

type Filtering struct {
	Enabled  bool   `yaml:"enabled"`
	Tool     string `yaml:"tool"`
	MergeAll bool   `yaml:"merge_all"`
}

type Resolution struct {
	Enabled              bool                 `yaml:"enabled"`
	Tool                 string               `yaml:"tool"`
	ResolverFile         string               `yaml:"resolver_file"`
	Validate             bool                 `yaml:"validate"`
	RateLimit            int                  `yaml:"rate_limit"`
	RecursiveSubfinder   RecursiveSubfinder   `yaml:"recursive_subfinder"`
}

type RecursiveSubfinder struct {
	Enabled    bool `yaml:"enabled"`
	AllSources bool `yaml:"all_sources"`
}

type Bruteforce struct {
	Enabled      bool   `yaml:"enabled"`
	Tool         string `yaml:"tool"`
	Wordlist     string `yaml:"wordlist"`
	ResolverFile string `yaml:"resolver_file"`
	Threads      int    `yaml:"threads"`
	Wildcards    bool   `yaml:"wildcards"`
}

type Permutations struct {
	Enabled     bool     `yaml:"enabled"`
	Tool        string   `yaml:"tool"`
	Patterns    []string `yaml:"patterns"`
	PipeToDNSx  bool     `yaml:"pipe_to_dnsx"`
}

// ============================================================================
// Phase 3: Infrastructure & Port Analysis
// ============================================================================

type Phase3Infrastructure struct {
	Enabled          bool             `yaml:"enabled"`
	PortScan         PortScan         `yaml:"port_scan"`
	ServiceDetection ServiceDetection `yaml:"service_detection"`
	VHostDiscovery   VHostDiscovery   `yaml:"vhost_discovery"`
	APIFuzzing       APIFuzzing       `yaml:"api_fuzzing"`
}

type PortScan struct {
	Enabled        bool   `yaml:"enabled"`
	Tool           string `yaml:"tool"`
	ScanAllPorts   bool   `yaml:"scan_all_ports"`
	TopPorts       int    `yaml:"top_ports"`
	FullPortRange  bool   `yaml:"full_port_range"`
	Concurrency    int    `yaml:"concurrency"`
	Rate           int    `yaml:"rate"`
	ExcludePorts   string `yaml:"exclude_ports"`
	ExcludeCDN     bool   `yaml:"exclude_cdn"`
	JSONOutput     bool   `yaml:"json_output"`
}

type ServiceDetection struct {
	Enabled         bool            `yaml:"enabled"`
	Tool            string          `yaml:"tool"`
	Options         string          `yaml:"options"`
	Timing          string          `yaml:"timing"`
}


type VHostDiscovery struct {
	Enabled    bool     `yaml:"enabled"`
	Tool       string   `yaml:"tool"`
	Wordlist   string   `yaml:"wordlist"`
	Patterns   []string `yaml:"patterns"`
	FilterSize bool     `yaml:"filter_size"`
	FilterWords bool    `yaml:"filter_words"`
}

type APIFuzzing struct {
	Enabled  bool     `yaml:"enabled"`
	Tool     string   `yaml:"tool"`
	Patterns []string `yaml:"patterns"`
	Wordlist string   `yaml:"wordlist"`
}

// ============================================================================
// Phase 4: Web Probing & Vulnerability Scanning
// ============================================================================

type Phase4WebProbing struct {
	Enabled         bool      `yaml:"enabled"`
	HTTPProbe       HTTPProbe `yaml:"http_probe"`
	Nuclei          Nuclei    `yaml:"nuclei"`
	Takeover        Takeover  `yaml:"takeover"`
	WPScanAPIToken  string    `yaml:"wpscan_api_token"`
}

type HTTPProbe struct {
	Enabled             bool   `yaml:"enabled"`
	Tool                string `yaml:"tool"`
	StatusCode          bool   `yaml:"status_code"`
	ContentLength       bool   `yaml:"content_length"`
	ContentType         bool   `yaml:"content_type"`
	LineCount           bool   `yaml:"line_count"`
	Title               bool   `yaml:"title"`
	BodyPreview         bool   `yaml:"body_preview"`
	Server              bool   `yaml:"server"`
	TechDetect          bool   `yaml:"tech_detect"`
	ProbeAllIPs         bool   `yaml:"probe_all_ips"`
	FollowRedirects     bool   `yaml:"follow_redirects"`
	FollowHostRedirects bool   `yaml:"follow_host_redirects"`
	IncludeResponse     bool   `yaml:"include_response"`
	RandomAgent         bool   `yaml:"random_agent"`
	Threads             int    `yaml:"threads"`
	RateLimit           int    `yaml:"rate_limit"`
	Timeout             int    `yaml:"timeout"`
	Retries             int    `yaml:"retries"`
	FilterCDN           bool   `yaml:"filter_cdn"`
	MatchCodes          string `yaml:"match_codes"`
}

type Nuclei struct {
	Enabled         bool     `yaml:"enabled"`
	Templates       []string `yaml:"templates"`
	Severity        string   `yaml:"severity"`
	Tags            string   `yaml:"tags"`
	Concurrency     int      `yaml:"concurrency"`
	RateLimit       int      `yaml:"rate_limit"`
	Timeout         int      `yaml:"timeout"`
	Retries         int      `yaml:"retries"`
	JSONOutput      bool     `yaml:"json_output"`
	MarkdownOutput  bool     `yaml:"markdown_output"`
	UpdateTemplates bool     `yaml:"update_templates"`
}

type Takeover struct {
	Enabled bool          `yaml:"enabled"`
	Tools   TakeoverTools `yaml:"tools"`
}

type TakeoverTools struct {
	Subjack SubjackConfig `yaml:"subjack"`
	Subzy   SubzyConfig   `yaml:"subzy"`
}

type SubjackConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Fingerprints string `yaml:"fingerprints"`
	Threads      int    `yaml:"threads"`
}

type SubzyConfig struct {
	Enabled     bool `yaml:"enabled"`
	TargetsFile bool `yaml:"targets_file"`
	Concurrency int  `yaml:"concurrency"`
}

// ============================================================================
// Phase 5: Deep Content & JavaScript Analysis
// ============================================================================

type Phase5ContentAnalysis struct {
	Enabled        bool           `yaml:"enabled"`
	URLExtraction  URLExtraction  `yaml:"url_extraction"`
	SensitiveFiles SensitiveFiles `yaml:"sensitive_files"`
	JavaScript     JavaScript     `yaml:"javascript"`
}

type URLExtraction struct {
	Enabled  bool            `yaml:"enabled"`
	Waymore  WaymoreConfig   `yaml:"waymore"`
	Gau      GauConfig       `yaml:"gau"`
	Katana   KatanaConfig    `yaml:"katana"`
}

type WaymoreConfig struct {
	Enabled      bool `yaml:"enabled"`
	Mode         string `yaml:"mode"`
	InputDomain  bool `yaml:"input_domain"`
	OutputURLs   bool `yaml:"output_urls"`
	Limit        int  `yaml:"limit"`
}

type GauConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Providers          string `yaml:"providers"`
	Threads            int    `yaml:"threads"`
	Verbose            bool   `yaml:"verbose"`
	IncludeSubdomains  bool   `yaml:"include_subdomains"`
	Blacklist          string `yaml:"blacklist"`
}

type KatanaConfig struct {
	Enabled         bool   `yaml:"enabled"`
	MaxDepth        int    `yaml:"max_depth"`
	JSCrawl         bool   `yaml:"js_crawl"`
	CrawlDuration   int    `yaml:"crawl_duration"`
	CrawlScope      string `yaml:"crawl_scope"`
	ExtractRobots   bool   `yaml:"extract_robots"`
	ExtractSitemap  bool   `yaml:"extract_sitemap"`
	Concurrency     int    `yaml:"concurrency"`
	Parallelism     int    `yaml:"parallelism"`
	RateLimit       int    `yaml:"rate_limit"`
}

type SensitiveFiles struct {
	Enabled      bool                 `yaml:"enabled"`
	Extensions   SensitiveExtensions  `yaml:"extensions"`
	GrepEnabled  bool                 `yaml:"grep_enabled"`
	GrepPattern  string               `yaml:"grep_pattern"`
}

type SensitiveExtensions struct {
	Documents []string `yaml:"documents"`
	Data      []string `yaml:"data"`
	Databases []string `yaml:"databases"`
	Backups   []string `yaml:"backups"`
	Configs   []string `yaml:"configs"`
	Source    []string `yaml:"source"`
}

type JavaScript struct {
	Enabled            bool               `yaml:"enabled"`
	Discovery          JSDiscovery        `yaml:"discovery"`
	EndpointExtraction EndpointExtraction `yaml:"endpoint_extraction"`
	SecretScanning     SecretScanning     `yaml:"secret_scanning"`
}

type JSDiscovery struct {
	GetJS  GetJSConfig  `yaml:"getjs"`
	GrepJS GrepJSConfig `yaml:"grep_js"`
}

type GetJSConfig struct {
	Enabled    bool `yaml:"enabled"`
	Complete   bool `yaml:"complete"`
	OutputFile bool `yaml:"output_file"`
}

type GrepJSConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Pattern      string `yaml:"pattern"`
	HTTPXFilter  bool   `yaml:"httpx_filter"`
}

type EndpointExtraction struct {
	Enabled    bool     `yaml:"enabled"`
	Patterns   []string `yaml:"patterns"`
	Tools      []string `yaml:"tools"`
	UniqueOnly bool     `yaml:"unique_only"`
	SortOutput bool     `yaml:"sort_output"`
}

type SecretScanning struct {
	Enabled  bool     `yaml:"enabled"`
	Patterns []string `yaml:"patterns"`
}

// ============================================================================
// Phase 6: Input & Parameter Fuzzing
// ============================================================================

type Phase6ParameterFuzzing struct {
	Enabled            bool               `yaml:"enabled"`
	ParameterDiscovery ParameterDiscovery `yaml:"parameter_discovery"`
	GFPatterns         GFPatterns         `yaml:"gf_patterns"`
	XSSTesting         XSSTesting         `yaml:"xss_testing"`
	LFITesting         LFITesting         `yaml:"lfi_testing"`
	SQLiTesting        SQLiTesting        `yaml:"sqli_testing"`
	FFUF               FFUFConfig         `yaml:"ffuf"`
}

type ParameterDiscovery struct {
	Enabled      bool     `yaml:"enabled"`
	Tool         string   `yaml:"tool"`
	Methods      []string `yaml:"methods"`
	Wordlist     string   `yaml:"wordlist"`
	Threads      int      `yaml:"threads"`
	Delay        int      `yaml:"delay"`
	Timeout      int      `yaml:"timeout"`
	OutputFormat string   `yaml:"output_format"`
}

type GFPatterns struct {
	Enabled    bool              `yaml:"enabled"`
	Patterns   GFPatternTypes    `yaml:"patterns"`
	Qsreplace  QsreplaceConfig   `yaml:"qsreplace"`
}

type GFPatternTypes struct {
	XSS      bool `yaml:"xss"`
	LFI      bool `yaml:"lfi"`
	SQLi     bool `yaml:"sqli"`
	SSRF     bool `yaml:"ssrf"`
	Redirect bool `yaml:"redirect"`
	RCE      bool `yaml:"rce"`
	IDOR     bool `yaml:"idor"`
}

type QsreplaceConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ReplaceValue string `yaml:"replace_value"`
}

type XSSTesting struct {
	Enabled      bool              `yaml:"enabled"`
	Preparation  XSSPreparation    `yaml:"preparation"`
	Dalfox       DalfoxConfig      `yaml:"dalfox"`
}

type XSSPreparation struct {
	GFXSS bool `yaml:"gf_xss"`
	URO   bool `yaml:"uro"`
	Gxss  bool `yaml:"gxss"`
	Rxss  bool `yaml:"rxss"`
}

type DalfoxConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Mode              string `yaml:"mode"`
	Mining            bool   `yaml:"mining"`
	MiningDict        bool   `yaml:"mining_dict"`
	WAFEvasion        bool   `yaml:"waf_evasion"`
	BlindXSS          bool   `yaml:"blind_xss"`
	Worker            int    `yaml:"worker"`
	Delay             int    `yaml:"delay"`
	Timeout           int    `yaml:"timeout"`
	CustomPayload     string `yaml:"custom_payload"`
	CustomAlertValue  string `yaml:"custom_alert_value"`
	Format            string `yaml:"format"`
	Silence           bool   `yaml:"silence"`
}

type LFITesting struct {
	Enabled      bool             `yaml:"enabled"`
	Preparation  LFIPreparation   `yaml:"preparation"`
	FFUF         LFIFFUFConfig    `yaml:"ffuf"`
}

type LFIPreparation struct {
	GFLFI     bool `yaml:"gf_lfi"`
	Qsreplace bool `yaml:"qsreplace"`
}

type LFIFFUFConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Wordlist     string `yaml:"wordlist"`
	MatchRegex   string `yaml:"match_regex"`
	MatchRegex2  string `yaml:"match_regex2"`
	FilterSize   bool   `yaml:"filter_size"`
	FilterLines  bool   `yaml:"filter_lines"`
	Threads      int    `yaml:"threads"`
	Rate         int    `yaml:"rate"`
}

type SQLiTesting struct {
	Enabled      bool            `yaml:"enabled"`
	Preparation  SQLiPreparation `yaml:"preparation"`
	SQLMap       SQLMapConfig    `yaml:"sqlmap"`
}

type SQLiPreparation struct {
	GFSQLi    bool `yaml:"gf_sqli"`
	Qsreplace bool `yaml:"qsreplace"`
}

type SQLMapConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Level     int    `yaml:"level"`
	Risk      int    `yaml:"risk"`
	Threads   int    `yaml:"threads"`
	Technique string `yaml:"technique"`
}

type FFUFConfig struct {
	Enabled          bool             `yaml:"enabled"`
	DirectoryFuzzing DirectoryFuzzing `yaml:"directory_fuzzing"`
	FileFuzzing      FileFuzzing      `yaml:"file_fuzzing"`
	Threads          int              `yaml:"threads"`
	Rate             int              `yaml:"rate"`
	Timeout          int              `yaml:"timeout"`
	FilterSize       bool             `yaml:"filter_size"`
	FilterLines      bool             `yaml:"filter_lines"`
	FilterWords      bool             `yaml:"filter_words"`
	AutoCalibrate    bool             `yaml:"auto_calibrate"`
	Recursion        bool             `yaml:"recursion"`
	RecursionDepth   int              `yaml:"recursion_depth"`
}

type DirectoryFuzzing struct {
	Enabled    bool     `yaml:"enabled"`
	Wordlists  []string `yaml:"wordlists"`
	Patterns   []string `yaml:"patterns"`
	MatchCodes string   `yaml:"match_codes"`
}

type FileFuzzing struct {
	Enabled    bool     `yaml:"enabled"`
	Extensions []string `yaml:"extensions"`
	Patterns   []string `yaml:"patterns"`
}

// ============================================================================
// Wordlists & Resolvers
// ============================================================================

type Wordlists struct {
	DNSBruteforce string `yaml:"dns_bruteforce"`
	Subdomains    string `yaml:"subdomains"`
	Directories   string `yaml:"directories"`
	Common        string `yaml:"common"`
	Parameters    string `yaml:"parameters"`
	LFI           string `yaml:"lfi"`
	XSS           string `yaml:"xss"`
	SQLi          string `yaml:"sqli"`
	VHosts        string `yaml:"vhosts"`
	API           string `yaml:"api"`
}

type Resolvers struct {
	File    string   `yaml:"file"`
	Trusted []string `yaml:"trusted"`
}

// ============================================================================
// Vulnerability Checks & Output
// ============================================================================

type VulnerabilityChecks struct {
	// Injection
	XSS    bool `yaml:"xss"`
	SQLi   bool `yaml:"sqli"`
	NoSQLi bool `yaml:"nosqli"`
	XMLi   bool `yaml:"xmli"`
	LDAPi  bool `yaml:"ldapi"`
	
	// Server-side
	SSRF bool `yaml:"ssrf"`
	RCE  bool `yaml:"rce"`
	LFI  bool `yaml:"lfi"`
	RFI  bool `yaml:"rfi"`
	
	// Access control
	IDOR         bool `yaml:"idor"`
	OpenRedirect bool `yaml:"open_redirect"`
	PathTraversal bool `yaml:"path_traversal"`
	
	// Logic flaws
	XXE  bool `yaml:"xxe"`
	CSRF bool `yaml:"csrf"`
	CORS bool `yaml:"cors"`
	
	// Information disclosure
	SensitiveData bool `yaml:"sensitive_data"`
	ErrorBased    bool `yaml:"error_based"`
}

type Output struct {
	// Report formats
	SaveHTMLReport     bool `yaml:"save_html_report"`
	SaveJSONReport     bool `yaml:"save_json_report"`
	SaveMarkdownReport bool `yaml:"save_markdown_report"`
	SaveTXTSummary     bool `yaml:"save_txt_summary"`
	
	// Screenshots
	Screenshots    bool   `yaml:"screenshots"`
	ScreenshotTool string `yaml:"screenshot_tool"`
	
	// Verbosity
	Verbose bool `yaml:"verbose"`
	Debug   bool `yaml:"debug"`
	
	// Real-time notifications
	DiscordWebhook  string `yaml:"discord_webhook"`
	SlackWebhook    string `yaml:"slack_webhook"`
	TelegramBot     string `yaml:"telegram_bot"`
	
	// Output structure
	TimestampDirs       bool `yaml:"timestamp_dirs"`
	OrganizeBySeverity  bool `yaml:"organize_by_severity"`
}

// ============================================================================
// Load Function
// ============================================================================

func Load(filepath string) (*Config, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("config dosyası okunamadı (%s): %w", filepath, err)
	}

	// Ortam değişkenlerini genişlet (ör: ${API_KEY}, $HOME)
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("config YAML parse hatası (%s): %w", filepath, err)
	}

	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config doğrulama hatası: %w", err)
	}
	return &cfg, nil
}

// SetDefaults ensures all critical settings have sane minimum values.
func (c *Config) SetDefaults() {
	if c.Settings.MaxWorkers <= 0 {
		c.Settings.MaxWorkers = 50
	}
	if c.Settings.MaxWorkers > 1000 {
		c.Settings.MaxWorkers = 1000
	}
	if c.Settings.Timeout <= 0 {
		c.Settings.Timeout = 10
	}
	if c.Settings.Timeout > 300 {
		c.Settings.Timeout = 300
	}
	if c.Settings.RetryAttempts <= 0 {
		c.Settings.RetryAttempts = 2
	}
	if c.Settings.RetryAttempts > 10 {
		c.Settings.RetryAttempts = 10
	}
	if c.Settings.UserAgent == "" {
		c.Settings.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	// Bug bounty araçlarında self-signed sertifikalı host'ları taramak için varsayılan: true
	if c.Settings.InsecureSkipVerify == nil {
		v := true
		c.Settings.InsecureSkipVerify = &v
	}
}

// Validate, config değerlerinin mantıklı olduğunu doğrular.
// Kritik olmayan sorunları uyarı olarak loglar, programı durdurmaz.
func (c *Config) Validate() error {
	if c.Settings.Resolvers != "" {
		if _, err := os.Stat(c.Settings.Resolvers); err != nil {
			// Resolvers dosyası yoksa uyarı ver ve yolu temizle — araçlar kendi default'larını kullanır
			fmt.Fprintf(os.Stderr, "[WARN] resolvers dosyası bulunamadı: %s — varsayılan DNS kullanılacak\n", c.Settings.Resolvers)
			c.Settings.Resolvers = ""
		}
	}
	return nil
}
