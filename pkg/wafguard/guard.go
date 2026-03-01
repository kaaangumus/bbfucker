package wafguard

import (
	"strings"
	"sync"
	"time"
)

// ============================================================================
// WAFGuard — WAF farkında tarama yöneticisi
//
// Kullanım:
//   g := wafguard.New()
//   g.Register("https://target.com", "Cloudflare")
//   delay := g.ScanDelay("Cloudflare")        // bekleme süresi
//   stealth := g.NeedsSteath("Cloudflare")    // agresif araçlar kapalı mı?
//   blocked := g.IsBlockBody(body)            // yanıt body'si block sayfası mı?
//   g.RecordBlock("https://target.com")       // bir block yaşandı, kaydet
//   killed := g.IsKilled("https://target.com") // 3+ block → taramayı durdur
// ============================================================================

// WAF türüne göre tarama arası bekleme süreleri
var wafDelays = map[string]time.Duration{
	"Cloudflare": 2500 * time.Millisecond,
	"Akamai":     3000 * time.Millisecond,
	"Imperva":    2500 * time.Millisecond,
	"F5 BIG-IP":  1500 * time.Millisecond,
	"AWS WAF":    2000 * time.Millisecond,
	"Sucuri":     2000 * time.Millisecond,
}

// WAF block yanıtlarını tanımlamak için body indikatörleri
var blockBodyIndicators = []string{
	"access denied",
	"you have been blocked",
	"request blocked",
	"security policy",
	"cf-ray",         // Cloudflare
	"incapsula incident",
	"imperva ddos",
	"ray id",
	"_ddos_",
	"site is blocked",
	"banned",
	"403 forbidden",
}

// WAFGuard tarama boyunca WAF durumunu ve block sayısını takip eder
type WAFGuard struct {
	mu         sync.RWMutex
	protected  map[string]string // host → WAF adı
	blockCount map[string]int    // host → kaç kez block yedi
}

const maxBlocksBeforeKill = 3

// New yeni bir WAFGuard örneği döndürür
func New() *WAFGuard {
	return &WAFGuard{
		protected:  make(map[string]string),
		blockCount: make(map[string]int),
	}
}

// Register bir hostu WAF korumalı olarak işaretler
func (g *WAFGuard) Register(host, wafName string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.protected[host] = wafName
}

// RegisterAll slice'tan toplu kayıt yapar (LiveHost.WAF != "")
func (g *WAFGuard) RegisterAll(hosts map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for host, waf := range hosts {
		g.protected[host] = waf
	}
}

// GetWAF bir hostun WAF adını döndürür (korumalı değilse "")
func (g *WAFGuard) GetWAF(host string) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.protected[host]
}

// IsProtected host WAF korumalı mı?
func (g *WAFGuard) IsProtected(host string) bool {
	return g.GetWAF(host) != ""
}

// ScanDelay WAF türüne göre request arası bekleme süresi döndürür.
// WAF bilinmiyorsa 2 saniye, değilse 0 döndürür.
func (g *WAFGuard) ScanDelay(wafName string) time.Duration {
	if wafName == "" {
		return 0
	}
	if d, ok := wafDelays[wafName]; ok {
		return d
	}
	return 2 * time.Second // bilinmeyen WAF için güvenli varsayılan
}

// NeedsStealth WAF'ın varlığında agresif tarama durdurulmalı mı?
// Her WAF için stealth gerekir. Yalnızca tool'lar buna göre davranır.
func (g *WAFGuard) NeedsStealth(wafName string) bool {
	return wafName != ""
}

// NucleiConcurrency WAF'lı hedefler için nuclei -c değeri
func (g *WAFGuard) NucleiConcurrency(wafName string) int {
	if wafName == "" {
		return 0 // varsayılan kullanılsın
	}
	return 3
}

// NucleiRateLimit WAF'lı hedefler için nuclei -rate-limit değeri
func (g *WAFGuard) NucleiRateLimit(wafName string) int {
	if wafName == "" {
		return 0
	}
	return 15
}

// IsBlockBody HTTP response body'sinin WAF block sayfası olup olmadığını kontrol eder
func (g *WAFGuard) IsBlockBody(body string) bool {
	lower := strings.ToLower(body)
	for _, indicator := range blockBodyIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// IsBlockStatusCode 403/429/503 block durumu mu?
func (g *WAFGuard) IsBlockStatusCode(statusCode int) bool {
	return statusCode == 403 || statusCode == 429 || statusCode == 503
}

// RecordBlock bir hostta block yaşandığını kaydeder
func (g *WAFGuard) RecordBlock(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockCount[host]++
}

// IsKilled 3+ block sonrası host tamamen tarama dışı mı?
func (g *WAFGuard) IsKilled(host string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.blockCount[host] >= maxBlocksBeforeKill
}

// BlockCount bir hostun toplam block sayısını döndürür
func (g *WAFGuard) BlockCount(host string) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.blockCount[host]
}

// ProtectedHosts WAF korumalı tüm hostları döndürür
func (g *WAFGuard) ProtectedHosts() map[string]string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]string, len(g.protected))
	for k, v := range g.protected {
		out[k] = v
	}
	return out
}

// SkipReason bir URL için taramanın neden atlandığını açıklar
func (g *WAFGuard) SkipReason(host string) string {
	if g.IsKilled(host) {
		return "WAF block limiti aşıldı (" + g.protected[host] + "), tarama durduruldu"
	}
	if g.IsProtected(host) {
		return "WAF korumalı (" + g.GetWAF(host) + "), agresif tarama atlandı"
	}
	return ""
}
