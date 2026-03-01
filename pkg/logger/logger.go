package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ============================================================================
// Log Levels
// ============================================================================

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Log Entry — structured log satırı
// ============================================================================

type Entry struct {
	Time    string            `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"msg"`
	Fields  map[string]string `json:"fields,omitempty"`
	Caller  string            `json:"caller,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// ============================================================================
// Logger — merkezi log yöneticisi
// ============================================================================

type Logger struct {
	mu       *sync.Mutex
	level    Level
	fields   map[string]string
	logFile  *os.File
	console  io.Writer
	filePath string

	// Renkli terminal çıktısı fonksiyonları
	debugFn func(format string, a ...interface{}) string
	infoFn  func(format string, a ...interface{}) string
	warnFn  func(format string, a ...interface{}) string
	errorFn func(format string, a ...interface{}) string
	fatalFn func(format string, a ...interface{}) string

	// Son N hata (özet için) — pointer ile paylaşılır
	recentErrors *[]Entry
	maxRecent    int

	// İstatistikler — pointer ile paylaşılır
	stats *LogStats
}

type LogStats struct {
	DebugCount int `json:"debug_count"`
	InfoCount  int `json:"info_count"`
	WarnCount  int `json:"warn_count"`
	ErrorCount int `json:"error_count"`
	FatalCount int `json:"fatal_count"`
	StartTime  time.Time `json:"start_time"`
}

// ============================================================================
// Yapıcı — New / Global Instance
// ============================================================================

var defaultLogger *Logger

// Init, global logger'ı başlatır. main.go'dan çağrılmalıdır.
//
//	logger.Init(logger.Options{
//	    Level:   logger.LevelInfo,
//	    LogFile: "results/domain/scan.log",
//	    Console: true,
//	})
func Init(opts Options) error {
	l, err := New(opts)
	if err != nil {
		return err
	}
	defaultLogger = l
	return nil
}

// Default, global logger'ı döndürür. Init çağrılmadıysa fallback oluşturur.
func Default() *Logger {
	if defaultLogger == nil {
		defaultLogger, _ = New(Options{Level: LevelInfo, Console: true})
	}
	return defaultLogger
}

// Close, log dosyasını kapatır.
func Close() {
	if defaultLogger != nil {
		defaultLogger.Shutdown()
	}
}

type Options struct {
	Level   Level  // Minimum log seviyesi
	LogFile string // JSON log dosyası yolu (boş = dosyaya yazma)
	Console bool   // Terminal çıktısı aktif mi
}

func New(opts Options) (*Logger, error) {
	initialErrors := make([]Entry, 0, 50)
	l := &Logger{
		mu:       &sync.Mutex{},
		level:    opts.Level,
		fields:   make(map[string]string),
		console:  os.Stdout,
		debugFn:  color.New(color.FgHiBlack).SprintfFunc(),
		infoFn:   color.New(color.FgCyan).SprintfFunc(),
		warnFn:   color.New(color.FgYellow).SprintfFunc(),
		errorFn:  color.New(color.FgRed).SprintfFunc(),
		fatalFn:  color.New(color.FgHiRed, color.Bold).SprintfFunc(),
		recentErrors: &initialErrors,
		maxRecent: 50,
		stats: &LogStats{
			StartTime: time.Now(),
		},
	}

	if !opts.Console {
		l.console = io.Discard
	}

	if opts.LogFile != "" {
		dir := filepath.Dir(opts.LogFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("log dizini oluşturulamadı: %w", err)
		}
		f, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("log dosyası açılamadı: %w", err)
		}
		l.logFile = f
		l.filePath = opts.LogFile
	}

	return l, nil
}

// Shutdown, log dosyasını kapatır ve özet istatistikleri yazar.
func (l *Logger) Shutdown() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.logFile != nil {
		// Son özet satırı yaz
		summary := Entry{
			Time:    time.Now().Format(time.RFC3339),
			Level:   "SUMMARY",
			Message: fmt.Sprintf("Log session ended — D:%d I:%d W:%d E:%d F:%d (%.1fs)", l.stats.DebugCount, l.stats.InfoCount, l.stats.WarnCount, l.stats.ErrorCount, l.stats.FatalCount, time.Since(l.stats.StartTime).Seconds()),
		}
		data, _ := json.Marshal(summary)
		l.logFile.Write(append(data, '\n'))
		l.logFile.Close()
		l.logFile = nil
	}
}

// ============================================================================
// With — Alt-logger oluşturma (ekstra context field'ları)
// ============================================================================

// With, ekstra alan(lar) eklenmiş yeni bir sub-logger döndürür.
// Orijinal logger değişmez, dosya ve console paylaşılır.
//
//	log := logger.Default().With("phase", "1", "tool", "subfinder")
//	log.Info("Subdomain taraması başladı")
func (l *Logger) With(keyvals ...string) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()

	sub := &Logger{
		mu:           l.mu,     // Paylaşımlı mutex — race condition önleme
		level:        l.level,
		fields:       make(map[string]string, len(l.fields)+len(keyvals)/2),
		logFile:      l.logFile,
		console:      l.console,
		filePath:     l.filePath,
		debugFn:      l.debugFn,
		infoFn:       l.infoFn,
		warnFn:       l.warnFn,
		errorFn:      l.errorFn,
		fatalFn:      l.fatalFn,
		recentErrors: l.recentErrors, // Paylaşımlı pointer
		maxRecent:    l.maxRecent,
		stats:        l.stats, // Paylaşımlı pointer — istatistik kaybı önleme
	}

	// Miras alanları kopyala
	for k, v := range l.fields {
		sub.fields[k] = v
	}
	// Yeni alanları ekle
	for i := 0; i+1 < len(keyvals); i += 2 {
		sub.fields[keyvals[i]] = keyvals[i+1]
	}

	return sub
}

// ============================================================================
// Log Seviyeleri — Public API
// ============================================================================

// Debug, sadece debug modunda görünen detaylı bilgi loglar.
func (l *Logger) Debug(msg string, keyvals ...string) {
	l.log(LevelDebug, msg, nil, keyvals...)
}

// Debugf, formatlı debug mesajı loglar.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(LevelDebug, fmt.Sprintf(format, args...), nil)
}

// Info, normal çalışma bilgisi loglar.
func (l *Logger) Info(msg string, keyvals ...string) {
	l.log(LevelInfo, msg, nil, keyvals...)
}

// Infof, formatlı bilgi mesajı loglar.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...), nil)
}

// Warn, uyarı mesajı loglar (hata değil ama dikkat gerektiren).
func (l *Logger) Warn(msg string, keyvals ...string) {
	l.log(LevelWarn, msg, nil, keyvals...)
}

// Warnf, formatlı uyarı mesajı loglar.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...), nil)
}

// Error, hata loglar. err nil ise mesaj yine de loglanır.
func (l *Logger) Error(msg string, err error, keyvals ...string) {
	l.log(LevelError, msg, err, keyvals...)
}

// Errorf, formatlı hata mesajı loglar.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...), nil)
}

// Fatal, kritik hata loglar ve programı sonlandırır.
func (l *Logger) Fatal(msg string, err error, keyvals ...string) {
	l.log(LevelFatal, msg, err, keyvals...)
	l.Shutdown()
	os.Exit(1)
}

// ============================================================================
// Global Kısayollar — logger.Info(...) şeklinde kullanım
// ============================================================================

func Debug(msg string, keyvals ...string)            { Default().Debug(msg, keyvals...) }
func Debugf(format string, args ...interface{})       { Default().Debugf(format, args...) }
func Info(msg string, keyvals ...string)              { Default().Info(msg, keyvals...) }
func Infof(format string, args ...interface{})        { Default().Infof(format, args...) }
func Warn(msg string, keyvals ...string)              { Default().Warn(msg, keyvals...) }
func Warnf(format string, args ...interface{})        { Default().Warnf(format, args...) }
func Error(msg string, err error, keyvals ...string)  { Default().Error(msg, err, keyvals...) }
func Errorf(format string, args ...interface{})       { Default().Errorf(format, args...) }
func Fatal(msg string, err error, keyvals ...string)  { Default().Fatal(msg, err, keyvals...) }

// ============================================================================
// İstatistik & Hata Özeti
// ============================================================================

// Stats, mevcut log istatistiklerini döndürür.
func (l *Logger) Stats() LogStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return *l.stats
}

// RecentErrors, son N hata entry'sini döndürür.
func (l *Logger) RecentErrors() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	copied := make([]Entry, len(*l.recentErrors))
	copy(copied, *l.recentErrors)
	return copied
}

// PrintSummary, tarama sonunda log özetini terminale yazdırır.
func (l *Logger) PrintSummary() {
	l.mu.Lock()
	stats := *l.stats
	errors := make([]Entry, len(*l.recentErrors))
	copy(errors, *l.recentErrors)
	l.mu.Unlock()

	elapsed := time.Since(stats.StartTime)

	fmt.Fprintln(l.console)
	fmt.Fprintln(l.console, color.CyanString("📋 LOG ÖZETİ"))
	fmt.Fprintf(l.console, "  Süre: %s\n", elapsed.Round(time.Second))
	fmt.Fprintf(l.console, "  Debug: %d | Info: %d | Warn: %s | Error: %s | Fatal: %s\n",
		stats.DebugCount,
		stats.InfoCount,
		color.YellowString("%d", stats.WarnCount),
		color.RedString("%d", stats.ErrorCount),
		color.HiRedString("%d", stats.FatalCount),
	)

	if len(errors) > 0 {
		shown := min(5, len(errors))
		fmt.Fprintf(l.console, "\n  %s\n", color.RedString("Son %d hata:", shown))
		for i := len(errors) - shown; i < len(errors); i++ {
			e := errors[i]
			errStr := ""
			if e.Error != "" {
				errStr = " — " + e.Error
			}
			fmt.Fprintf(l.console, "    • [%s] %s%s\n", e.Level, e.Message, errStr)
		}
	}

	if l.filePath != "" {
		fmt.Fprintf(l.console, "\n  📄 Detaylı log: %s\n", color.CyanString(l.filePath))
	}
}

// ============================================================================
// Dahili log yazma motoru
// ============================================================================

func (l *Logger) log(level Level, msg string, err error, keyvals ...string) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// İstatistik güncelle
	switch level {
	case LevelDebug:
		l.stats.DebugCount++
	case LevelInfo:
		l.stats.InfoCount++
	case LevelWarn:
		l.stats.WarnCount++
	case LevelError:
		l.stats.ErrorCount++
	case LevelFatal:
		l.stats.FatalCount++
	}

	now := time.Now()

	// Entry oluştur
	entry := Entry{
		Time:    now.Format(time.RFC3339),
		Level:   level.String(),
		Message: msg,
	}

	// Fields birleştir (logger fields + inline keyvals)
	if len(l.fields) > 0 || len(keyvals) > 0 {
		entry.Fields = make(map[string]string, len(l.fields)+len(keyvals)/2)
		for k, v := range l.fields {
			entry.Fields[k] = v
		}
		for i := 0; i+1 < len(keyvals); i += 2 {
			entry.Fields[keyvals[i]] = keyvals[i+1]
		}
	}

	if err != nil {
		entry.Error = err.Error()
	}

	// Caller bilgisi (sadece error/fatal için — performans)
	if level >= LevelError {
		if _, file, line, ok := runtime.Caller(2); ok {
			// Sadece "pkg/..." kısmını göster
			short := file
			if idx := strings.Index(file, "pkg/"); idx != -1 {
				short = file[idx:]
			} else if idx := strings.LastIndex(file, "/"); idx != -1 {
				short = file[idx+1:]
			}
			entry.Caller = fmt.Sprintf("%s:%d", short, line)
		}
	}

	// ── Terminal çıktısı ─────────────────────────────────────────────────
	l.writeConsole(level, now, entry)

	// ── Dosya çıktısı (JSON Lines) ──────────────────────────────────────
	if l.logFile != nil {
		data, _ := json.Marshal(entry)
		l.logFile.Write(append(data, '\n'))
	}

	// ── Son hatalar listesi ─────────────────────────────────────────────
	if level >= LevelError {
		*l.recentErrors = append(*l.recentErrors, entry)
		if len(*l.recentErrors) > l.maxRecent {
			*l.recentErrors = (*l.recentErrors)[1:]
		}
	}
}

func (l *Logger) writeConsole(level Level, now time.Time, entry Entry) {
	timestamp := now.Format("15:04:05")

	var prefix string
	switch level {
	case LevelDebug:
		prefix = l.debugFn("[DBG]")
	case LevelInfo:
		prefix = l.infoFn("[INF]")
	case LevelWarn:
		prefix = l.warnFn("[WRN]")
	case LevelError:
		prefix = l.errorFn("[ERR]")
	case LevelFatal:
		prefix = l.fatalFn("[FTL]")
	}

	// Mesaj
	line := fmt.Sprintf("%s %s %s", color.HiBlackString(timestamp), prefix, entry.Message)

	// Fields (varsa tek satırda)
	if len(entry.Fields) > 0 {
		parts := make([]string, 0, len(entry.Fields))
		for k, v := range entry.Fields {
			parts = append(parts, color.HiBlackString("%s=", k)+v)
		}
		line += " " + strings.Join(parts, " ")
	}

	// Error
	if entry.Error != "" {
		line += " " + l.errorFn("err=%s", entry.Error)
	}

	// Caller
	if entry.Caller != "" {
		line += " " + color.HiBlackString("(%s)", entry.Caller)
	}

	fmt.Fprintln(l.console, line)
}

// ============================================================================
// Yardımcı — Level config'den parse
// ============================================================================

// ParseLevel, string seviyeyi Level'a çevirir.
//
//	"debug" → LevelDebug, "info" → LevelInfo, vb.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "dbg":
		return LevelDebug
	case "info", "inf":
		return LevelInfo
	case "warn", "warning", "wrn":
		return LevelWarn
	case "error", "err":
		return LevelError
	case "fatal", "ftl":
		return LevelFatal
	default:
		return LevelInfo
	}
}

// LevelFromConfig, Verbose/Debug flag'lerine göre minimum seviyeyi belirler.
func LevelFromConfig(verbose, debug bool) Level {
	if debug {
		return LevelDebug
	}
	if verbose {
		return LevelInfo
	}
	return LevelWarn
}
