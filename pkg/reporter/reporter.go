package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

type Reporter struct {
	outputDir string
	verbose   bool
}

// reportView — HTML/TXT template'e gönderilen tek struct; JSON üzerinden doldurulur
type reportView struct {
	Domain               string
	ScanDate             string
	SubdomainsCount      int
	URLsCount            int
	LiveHostsCount       int
	VulnerabilitiesCount int
	SensitiveFilesCount  int
	Subdomains           []string
	URLs                 []string
	LiveHosts            []liveHostView
	Vulnerabilities      []vulnView
	SensitiveFiles       []sensitiveFileView
}

type liveHostView struct {
	URL           string
	StatusCode    int
	Title         string
	WAF           string
	CMS           string
	CMSVersion    string
	Technologies  []string
	ContentLength int
}

type vulnView struct {
	Type        string
	Severity    string
	URL         string
	Parameter   string
	Description string
}

type sensitiveFileView struct {
	URL      string
	Type     string
	Size     int
	Content  string // İlk 200 karakter
}

func NewReporter(outputDir string, verbose bool) *Reporter {
	return &Reporter{outputDir: outputDir, verbose: verbose}
}

func (r *Reporter) Generate(data interface{}) {
	r.generateJSON(data)
	r.generateHTML(data)
	r.generateSummary(data)
	r.saveSensitiveFiles(data) // Hassas dosyaları kaydet

	if r.verbose {
		color.Green("\n[✓] Raporlar oluşturuldu:")
		color.Green("  - JSON: %s", filepath.Join(r.outputDir, "report.json"))
		color.Green("  - HTML: %s", filepath.Join(r.outputDir, "report.html"))
		color.Green("  - Özet: %s", filepath.Join(r.outputDir, "summary.txt"))
		color.Green("  - Hassas: %s", filepath.Join(r.outputDir, "sensitive_files/"))
	}
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

func (r *Reporter) generateJSON(data interface{}) {
	fp := filepath.Join(r.outputDir, "report.json")
	f, err := os.Create(fp)
	if err != nil {
		logger.Errorf("JSON rapor dosyası oluşturulamadı: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		logger.Errorf("JSON rapor yazma hatası: %v", err)
	}
}

// ─── Veri dönüşümü ───────────────────────────────────────────────────────────

// buildView — herhangi bir struct'ı JSON üzerinden alarak reportView'a çevirir.
// Böylece ScanResults veya başka bir struct fark etmez.
func buildView(data interface{}) reportView {
	raw, err := json.Marshal(data)
	if err != nil {
		logger.Errorf("rapor verisi marshal hatası: %v", err)
		return reportView{}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		logger.Errorf("rapor verisi unmarshal hatası: %v", err)
		return reportView{}
	}

	view := reportView{
		Domain:   strVal(m["domain"]),
		ScanDate: strVal(m["scan_date"]),
	}
	if view.ScanDate == "" {
		view.ScanDate = time.Now().Format("2006-01-02 15:04:05")
	}

	if list, ok := m["subdomains"].([]interface{}); ok {
		view.SubdomainsCount = len(list)
		for _, s := range list {
			view.Subdomains = append(view.Subdomains, strVal(s))
		}
	}

	if list, ok := m["urls"].([]interface{}); ok {
		view.URLsCount = len(list)
		for _, s := range list {
			view.URLs = append(view.URLs, strVal(s))
		}
	}

	if list, ok := m["live_hosts"].([]interface{}); ok {
		view.LiveHostsCount = len(list)
		for _, item := range list {
			if obj, ok := item.(map[string]interface{}); ok {
				lh := liveHostView{
					URL:           strVal(obj["url"]),
					StatusCode:    intVal(obj["status_code"]),
					Title:         strVal(obj["title"]),
					WAF:           strVal(obj["waf"]),
					CMS:           strVal(obj["cms"]),
					CMSVersion:    strVal(obj["cms_version"]),
					ContentLength: intVal(obj["content_length"]),
				}
				if techs, ok := obj["technologies"].([]interface{}); ok {
					for _, t := range techs {
						lh.Technologies = append(lh.Technologies, strVal(t))
					}
				}
				view.LiveHosts = append(view.LiveHosts, lh)
			}
		}
	}

	if list, ok := m["vulnerabilities"].([]interface{}); ok {
		view.VulnerabilitiesCount = len(list)
		for _, item := range list {
			if obj, ok := item.(map[string]interface{}); ok {
				view.Vulnerabilities = append(view.Vulnerabilities, vulnView{
					Type:        strVal(obj["type"]),
					Severity:    strVal(obj["severity"]),
					URL:         strVal(obj["url"]),
					Parameter:   strVal(obj["parameter"]),
					Description: strVal(obj["description"]),
				})
			}
		}
	}

	// Hassas dosyalar
	if list, ok := m["sensitive_files"].([]interface{}); ok {
		view.SensitiveFilesCount = len(list)
		for _, item := range list {
			if obj, ok := item.(map[string]interface{}); ok {
				content := strVal(obj["content"])
				if len(content) > 200 {
					content = content[:200] + "..."
				}
				view.SensitiveFiles = append(view.SensitiveFiles, sensitiveFileView{
					URL:     strVal(obj["url"]),
					Type:    strVal(obj["type"]),
					Size:    intVal(obj["size"]),
					Content: content,
				})
			}
		}
	}

	return view
}

func strVal(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func intVal(v interface{}) int {
	if v == nil {
		return 0
	}
	if n, ok := v.(float64); ok {
		return int(n)
	}
	return 0
}

// ─── HTML ─────────────────────────────────────────────────────────────────────

func (r *Reporter) generateHTML(data interface{}) {
	view := buildView(data)

	const htmlTmpl = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BBFucker — {{.Domain}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0f0f1a;color:#e0e0e0;padding:20px}
a{color:#7c8cf8;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1300px;margin:0 auto}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);border:1px solid #2a2a4a;border-radius:12px;padding:40px;text-align:center;margin-bottom:20px}
.header h1{font-size:2.2em;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header .domain{font-size:1.3em;color:#c0c0ff;margin-top:10px}
.header .date{color:#666;font-size:.9em;margin-top:6px}
.badge{display:inline-block;background:rgba(102,126,234,.15);border:1px solid rgba(102,126,234,.35);color:#7c8cf8;padding:3px 12px;border-radius:20px;margin:6px 3px;font-size:.82em}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px}
.sc{background:#1a1a2e;border:1px solid #2a2a4a;border-radius:10px;padding:22px;text-align:center}
.sc .num{font-size:2.6em;font-weight:700}.sc .lbl{color:#666;font-size:.78em;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.blue{color:#667eea}.green{color:#56cfb2}.yellow{color:#f7c59f}.red{color:#fc5c7d}.purple{color:#9d50bb}
.card{background:#1a1a2e;border:1px solid #2a2a4a;border-radius:10px;padding:24px;margin-bottom:18px}
.ctitle{font-size:1.15em;color:#667eea;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #2a2a4a}
table{width:100%;border-collapse:collapse;font-size:.88em}
th{background:#0d0d1a;color:#666;padding:9px 13px;text-align:left;font-weight:600;text-transform:uppercase;font-size:.75em;letter-spacing:.5px}
td{padding:9px 13px;border-bottom:1px solid #1a1a30;vertical-align:middle}
tr:last-child td{border:none}tr:hover td{background:rgba(102,126,234,.04)}
code{background:#0d0d1a;border:1px solid #1e1e36;padding:2px 7px;border-radius:4px;font-family:monospace;font-size:.83em;word-break:break-all}
.tech-tag{display:inline-block;background:rgba(157,80,187,.15);border:1px solid rgba(157,80,187,.35);color:#c19bd9;padding:1px 6px;border-radius:10px;font-size:.7em;margin:1px}
.waf-tag{background:rgba(252,92,125,.15);border:1px solid rgba(252,92,125,.35);color:#fc5c7d}
.cms-tag{background:rgba(86,207,178,.15);border:1px solid rgba(86,207,178,.35);color:#56cfb2}
.sev{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:600;font-size:.75em;text-transform:uppercase}
.sev.critical{background:rgba(252,92,125,.2);color:#fc5c7d;border:1px solid rgba(252,92,125,.3)}
.sev.high{background:rgba(247,197,159,.2);color:#f7c59f;border:1px solid rgba(247,197,159,.3)}
.sev.medium{background:rgba(255,209,102,.2);color:#ffd166;border:1px solid rgba(255,209,102,.3)}
.sev.low{background:rgba(86,207,178,.2);color:#56cfb2;border:1px solid rgba(86,207,178,.3)}
.sev.info{background:rgba(102,126,234,.2);color:#667eea;border:1px solid rgba(102,126,234,.3)}
.scode{display:inline-block;padding:2px 8px;border-radius:4px;font-family:monospace;font-weight:700;font-size:.85em}
.s200{background:rgba(86,207,178,.2);color:#56cfb2}
.s301,.s302{background:rgba(102,126,234,.2);color:#667eea}
.s401,.s403{background:rgba(247,197,159,.2);color:#f7c59f}
.s500{background:rgba(252,92,125,.2);color:#fc5c7d}
.s0{background:rgba(255,255,255,.06);color:#777}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:5px}
.gi{background:#1a1a30;border:1px solid #2a2a4a;padding:8px 12px;border-radius:6px;font-size:.88em;word-break:break-all}
.empty{text-align:center;color:#666;padding:40px;font-style:italic}
.gi{background:#0d0d1a;border:1px solid #1a1a30;border-radius:5px;padding:6px 10px;font-family:monospace;font-size:.82em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#a0c8ff}
.empty{text-align:center;padding:36px;color:#444;font-style:italic}
footer{text-align:center;padding:18px;color:#333;font-size:.82em;margin-top:8px}
</style>
</head>
<body>
<div class="wrap">

<div class="header">
  <h1>🔍 BBFucker Report</h1>
  <div class="domain">{{.Domain}}</div>
  <div class="date">{{.ScanDate}}</div>
  <div style="margin-top:12px">
    <span class="badge">⚡ Go Edition</span>
    <span class="badge">6-Phase Pipeline</span>
  </div>
</div>

<div class="stats">
  <div class="sc"><div class="num blue">{{.SubdomainsCount}}</div><div class="lbl">Subdomain</div></div>
  <div class="sc"><div class="num yellow">{{.URLsCount}}</div><div class="lbl">URL</div></div>
  <div class="sc"><div class="num green">{{.LiveHostsCount}}</div><div class="lbl">Aktif Host</div></div>
  <div class="sc"><div class="num red">{{.VulnerabilitiesCount}}</div><div class="lbl">Açık</div></div>
  <div class="sc"><div class="num purple">{{.SensitiveFilesCount}}</div><div class="lbl">Hassas Dosya</div></div>
</div>

{{if .Vulnerabilities}}
<div class="card">
  <div class="ctitle">🚨 Bulunan Açıklar ({{.VulnerabilitiesCount}})</div>
  <table>
    <tr><th>Tür</th><th>Severity</th><th>URL</th><th>Parametre</th><th>Açıklama</th></tr>
    {{range .Vulnerabilities}}
    <tr>
      <td>{{.Type}}</td>
      <td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
      <td><code>{{.URL}}</code></td>
      <td>{{if .Parameter}}<code>{{.Parameter}}</code>{{else}}—{{end}}</td>
      <td>{{if .Description}}{{.Description}}{{else}}—{{end}}</td>
    </tr>
    {{end}}
  </table>
</div>
{{end}}

{{if .LiveHosts}}
<div class="card">
  <div class="ctitle">🌐 Aktif Hostlar ({{.LiveHostsCount}})</div>
  <table>
    <tr><th>URL</th><th>Status</th><th>Başlık</th><th>WAF</th><th>CMS</th><th>Teknolojiler</th></tr>
    {{range .LiveHosts}}
    <tr>
      <td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
      <td>
        {{if eq .StatusCode 200}}<span class="scode s200">200</span>
        {{else if eq .StatusCode 301}}<span class="scode s301">301</span>
        {{else if eq .StatusCode 302}}<span class="scode s302">302</span>
        {{else if eq .StatusCode 401}}<span class="scode s401">401</span>
        {{else if eq .StatusCode 403}}<span class="scode s403">403</span>
        {{else if eq .StatusCode 500}}<span class="scode s500">500</span>
        {{else}}<span class="scode s0">{{.StatusCode}}</span>{{end}}
      </td>
      <td>{{if .Title}}{{.Title}}{{else}}—{{end}}</td>
      <td>{{if .WAF}}<span class="tech-tag waf-tag">{{.WAF}}</span>{{else}}—{{end}}</td>
      <td>{{if .CMS}}<span class="tech-tag cms-tag">{{.CMS}}{{if .CMSVersion}} {{.CMSVersion}}{{end}}</span>{{else}}—{{end}}</td>
      <td>{{range .Technologies}}<span class="tech-tag">{{.}}</span>{{end}}</td>
    </tr>
    {{end}}
  </table>
</div>
{{end}}

<div class="card">
  <div class="ctitle">🔎 Subdomainler ({{.SubdomainsCount}})</div>
  {{if .Subdomains}}
  <div class="grid">{{range .Subdomains}}<div class="gi" title="{{.}}">{{.}}</div>{{end}}</div>
  {{else}}<div class="empty">Subdomain bulunamadı</div>{{end}}
</div>

{{if .URLs}}
<div class="card">
  <div class="ctitle">🔗 URL'ler ({{.URLsCount}})</div>
  <div class="grid">{{range .URLs}}<div class="gi" title="{{.}}"><a href="{{.}}" target="_blank">{{.}}</a></div>{{end}}</div>
</div>
{{end}}

{{if .SensitiveFiles}}
<div class="card">
  <div class="ctitle">🔒 Hassas Dosyalar ({{.SensitiveFilesCount}})</div>
  <table>
    <tr><th>URL</th><th>Tür</th><th>Boyut</th><th>İçerik Önizlemesi</th></tr>
    {{range .SensitiveFiles}}
    <tr>
      <td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
      <td><span class="tech-tag">{{.Type}}</span></td>
      <td>{{.Size}} byte</td>
      <td><code>{{.Content}}</code></td>
    </tr>
    {{end}}
  </table>
</div>
{{end}}

<footer>⚡ Generated by BBFucker — 6-Phase Professional Bug Bounty Pipeline</footer>
</div>
</body>
</html>`

	tmpl, err := template.New("r").Parse(htmlTmpl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reporter] HTML parse hatası: %v\n", err)
		return
	}

	fp := filepath.Join(r.outputDir, "report.html")
	f, err := os.Create(fp)
	if err != nil {
		return
	}
	defer f.Close()

	if err := tmpl.Execute(f, view); err != nil {
		logger.Errorf("HTML rapor render hatası: %v", err)
		fmt.Fprintf(os.Stderr, "[reporter] HTML execute hatası: %v\n", err)
	}
}

// ─── Summary TXT ──────────────────────────────────────────────────────────────

func (r *Reporter) generateSummary(data interface{}) {
	view := buildView(data)

	sep := strings.Repeat("=", 70)
	dash := strings.Repeat("-", 70)
	var sb strings.Builder
	l := func(s string) { sb.WriteString(s + "\n") }

	l(sep)
	l("BUG BOUNTY TARAMA RAPORU — BBFucker (Go Edition)")
	l(sep)
	l(fmt.Sprintf("Domain : %s", view.Domain))
	l(fmt.Sprintf("Tarih  : %s", view.ScanDate))
	l(sep)
	l("")
	l("ÖZET")
	l(dash)
	l(fmt.Sprintf("  Subdomain    : %d", view.SubdomainsCount))
	l(fmt.Sprintf("  URL          : %d", view.URLsCount))
	l(fmt.Sprintf("  Aktif Host   : %d", view.LiveHostsCount))
	l(fmt.Sprintf("  Açık Bulundu : %d", view.VulnerabilitiesCount))
	l("")

	if len(view.Vulnerabilities) > 0 {
		l("AÇIKLAR")
		l(dash)
		for _, v := range view.Vulnerabilities {
			l(fmt.Sprintf("  [%s] %s — %s", strings.ToUpper(v.Severity), v.Type, v.URL))
			if v.Parameter != "" {
				l(fmt.Sprintf("         Parametre: %s", v.Parameter))
			}
			if v.Description != "" {
				l(fmt.Sprintf("         Açıklama : %s", v.Description))
			}
		}
		l("")
	}

	if len(view.LiveHosts) > 0 {
		l("AKTIF HOSTLAR")
		l(dash)
		for _, h := range view.LiveHosts {
			line := fmt.Sprintf("  [%d] %s", h.StatusCode, h.URL)
			if h.Title != "" {
				line += fmt.Sprintf(" (%s)", h.Title)
			}
			l(line)
		}
		l("")
	}

	if len(view.Subdomains) > 0 {
		l("SUBDOMAINLER")
		l(dash)
		for _, s := range view.Subdomains {
			l("  " + s)
		}
		l("")
	}

	l(sep)
	l("⚡ Powered by BBFucker — ULTRA FAST!")
	l(sep)

	// UTF-8 BOM ekle — Windows araçları (Notepad, Excel) dosyayı doğru okusun
	bom := "\xef\xbb\xbf"
	if err := os.WriteFile(filepath.Join(r.outputDir, "summary.txt"), []byte(bom+sb.String()), 0644); err != nil {
		logger.Errorf("summary.txt yazma hatası: %v", err)
	}
}

// ─── Hassas Dosya Kaydetme ──────────────────────────────────────────────────────

func (r *Reporter) saveSensitiveFiles(data interface{}) {
	raw, err := json.Marshal(data)
	if err != nil {
		logger.Errorf("sensitive files marshal hatası: %v", err)
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		logger.Errorf("sensitive files unmarshal hatası: %v", err)
		return
	}
	
	sensitiveList, ok := m["sensitive_files"].([]interface{})
	if !ok || len(sensitiveList) == 0 {
		return
	}
	
	// sensitive_files klasörü oluştur
	sensDir := filepath.Join(r.outputDir, "sensitive_files")
	if err := os.MkdirAll(sensDir, 0755); err != nil {
		logger.Errorf("sensitive_files dizini oluşturulamadı: %v", err)
		return
	}
	
	// Her hassas dosyayı kaydet
	for i, item := range sensitiveList {
		if obj, ok := item.(map[string]interface{}); ok {
			url := strVal(obj["url"])
			fileType := strVal(obj["type"])
			content := strVal(obj["content"])
			
			if url == "" || content == "" {
				continue
			}
			
			// Dosya adı: 001_backup.sql, 002_config.php, vb.
			filename := fmt.Sprintf("%03d_%s.txt", i+1, sanitizeFilename(fileType))
			if fileType == "" {
				filename = fmt.Sprintf("%03d_unknown.txt", i+1)
			}
			
			// Dosya içeriği: URL + içerik
			fileContent := fmt.Sprintf("URL: %s\nType: %s\nSize: %d bytes\n%s\n\n%s",
				url, fileType, intVal(obj["size"]), strings.Repeat("=", 80), content)
			
			os.WriteFile(filepath.Join(sensDir, filename), []byte(fileContent), 0644)
			
			if r.verbose {
				color.Green("  [SAVE] %s → %s", url, filename)
			}
		}
	}
	
	// İndeks dosyası oluştur
	var indexLines []string
	indexLines = append(indexLines, "HASSAS DOSYALAR İNDEKSİ")
	indexLines = append(indexLines, strings.Repeat("=", 50))
	indexLines = append(indexLines, "")
	
	for i, item := range sensitiveList {
		if obj, ok := item.(map[string]interface{}); ok {
			url := strVal(obj["url"])
			fileType := strVal(obj["type"])
			size := intVal(obj["size"])
			filename := fmt.Sprintf("%03d_%s.txt", i+1, sanitizeFilename(fileType))
			if fileType == "" {
				filename = fmt.Sprintf("%03d_unknown.txt", i+1)
			}
			
			indexLines = append(indexLines, fmt.Sprintf("%s", filename))
			indexLines = append(indexLines, fmt.Sprintf("  URL: %s", url))
			indexLines = append(indexLines, fmt.Sprintf("  Tür: %s", fileType))
			indexLines = append(indexLines, fmt.Sprintf("  Boyut: %d bytes", size))
			indexLines = append(indexLines, "")
		}
	}
	
	os.WriteFile(filepath.Join(sensDir, "index.txt"), []byte(strings.Join(indexLines, "\n")), 0644)
}

// sanitizeFilename — dosya adını Windows/Linux uyumlu hale getirir
func sanitizeFilename(s string) string {
	if s == "" {
		return "unknown"
	}
	// Zararlı karakterleri temizle
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "*", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "\"", "_")
	s = strings.ReplaceAll(s, "<", "_")
	s = strings.ReplaceAll(s, ">", "_")
	s = strings.ReplaceAll(s, "|", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return strings.ToLower(s)
}

