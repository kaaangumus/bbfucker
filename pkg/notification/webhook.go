package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bbfucker/pkg/logger"

	"github.com/fatih/color"
)

// Notifier webhook bildirimlerini yönetir
type Notifier struct {
	discordURL string
	slackURL   string
	verbose    bool
}

// NewNotifier yeni bir notifier oluşturur
func NewNotifier(discordURL, slackURL string, verbose bool) *Notifier {
	return &Notifier{
		discordURL: discordURL,
		slackURL:   slackURL,
		verbose:    verbose,
	}
}

// NotificationPayload bildirim verisi
type NotificationPayload struct {
	Domain          string
	Phase           string
	Message         string
	SubdomainCount  int
	VulnCount       int
	CriticalCount   int
	HighCount       int
	LiveHostCount   int
	Status          string // "started", "phase_complete", "completed", "error"
}

// DiscordPayload Discord webhook formatı
type DiscordPayload struct {
	Content string         `json:"content,omitempty"`
	Embeds  []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// SlackPayload Slack webhook formatı
type SlackPayload struct {
	Text        string             `json:"text,omitempty"`
	Username    string             `json:"username,omitempty"`
	IconEmoji   string             `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment  `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Title      string       `json:"title,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	Timestamp  int64        `json:"ts,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SendNotification bildirim gönderir
func (n *Notifier) SendNotification(payload NotificationPayload) error {
	var errs []error

	if n.discordURL != "" {
		if err := n.sendDiscord(payload); err != nil {
			errs = append(errs, fmt.Errorf("Discord: %w", err))
		}
	}

	if n.slackURL != "" {
		if err := n.sendSlack(payload); err != nil {
			errs = append(errs, fmt.Errorf("Slack: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}

	return nil
}

// sendDiscord Discord'a bildirim gönderir
func (n *Notifier) sendDiscord(payload NotificationPayload) error {
	embed := n.buildDiscordEmbed(payload)
	
	discordPayload := DiscordPayload{
		Embeds: []DiscordEmbed{embed},
	}

	return n.sendWebhook(n.discordURL, discordPayload, "Discord")
}

// sendSlack Slack'e bildirim gönderir
func (n *Notifier) sendSlack(payload NotificationPayload) error {
	attachment := n.buildSlackAttachment(payload)
	
	slackPayload := SlackPayload{
		Username:    "BBFucker",
		IconEmoji:   ":robot_face:",
		Attachments: []SlackAttachment{attachment},
	}

	return n.sendWebhook(n.slackURL, slackPayload, "Slack")
}

// buildDiscordEmbed Discord embed oluşturur
func (n *Notifier) buildDiscordEmbed(payload NotificationPayload) DiscordEmbed {
	embed := DiscordEmbed{
		Timestamp: time.Now().Format(time.RFC3339),
		Footer: &DiscordEmbedFooter{
			Text: "BBFucker v1.0",
		},
	}

	switch payload.Status {
	case "started":
		embed.Title = "🚀 Tarama Başlatıldı"
		embed.Color = 3447003 // Mavi
		embed.Description = fmt.Sprintf("Hedef: **%s**", payload.Domain)
		
	case "phase_complete":
		embed.Title = fmt.Sprintf("✅ %s Tamamlandı", payload.Phase)
		embed.Color = 3066993 // Yeşil
		embed.Description = payload.Message
		embed.Fields = n.buildStatsFields(payload)
		
	case "completed":
		embed.Title = "🎉 Tarama Tamamlandı"
		embed.Color = 3066993 // Yeşil
		embed.Description = fmt.Sprintf("**%s** için tarama başarıyla tamamlandı!", payload.Domain)
		embed.Fields = n.buildStatsFields(payload)
		
	case "error":
		embed.Title = "❌ Hata"
		embed.Color = 15158332 // Kırmızı
		embed.Description = payload.Message
	}

	return embed
}

// buildSlackAttachment Slack attachment oluşturur
func (n *Notifier) buildSlackAttachment(payload NotificationPayload) SlackAttachment {
	attachment := SlackAttachment{
		Footer:    "BBFucker v1.0",
		Timestamp: time.Now().Unix(),
	}

	switch payload.Status {
	case "started":
		attachment.Color = "good"
		attachment.Title = "🚀 Tarama Başlatıldı"
		attachment.Text = fmt.Sprintf("Hedef: *%s*", payload.Domain)
		
	case "phase_complete":
		attachment.Color = "good"
		attachment.Title = fmt.Sprintf("✅ %s Tamamlandı", payload.Phase)
		attachment.Text = payload.Message
		attachment.Fields = n.buildSlackStatsFields(payload)
		
	case "completed":
		attachment.Color = "good"
		attachment.Title = "🎉 Tarama Tamamlandı"
		attachment.Text = fmt.Sprintf("*%s* için tarama başarıyla tamamlandı!", payload.Domain)
		attachment.Fields = n.buildSlackStatsFields(payload)
		
	case "error":
		attachment.Color = "danger"
		attachment.Title = "❌ Hata"
		attachment.Text = payload.Message
	}

	return attachment
}

// buildStatsFields Discord için istatistik alanları oluşturur
func (n *Notifier) buildStatsFields(payload NotificationPayload) []DiscordEmbedField {
	var fields []DiscordEmbedField

	if payload.SubdomainCount > 0 {
		fields = append(fields, DiscordEmbedField{
			Name:   "📊 Subdomains",
			Value:  fmt.Sprintf("%d", payload.SubdomainCount),
			Inline: true,
		})
	}

	if payload.LiveHostCount > 0 {
		fields = append(fields, DiscordEmbedField{
			Name:   "🟢 Live Hosts",
			Value:  fmt.Sprintf("%d", payload.LiveHostCount),
			Inline: true,
		})
	}

	if payload.VulnCount > 0 {
		fields = append(fields, DiscordEmbedField{
			Name:   "🔴 Vulnerabilities",
			Value:  fmt.Sprintf("%d", payload.VulnCount),
			Inline: true,
		})
	}

	if payload.CriticalCount > 0 {
		fields = append(fields, DiscordEmbedField{
			Name:   "⚠️ Critical",
			Value:  fmt.Sprintf("%d", payload.CriticalCount),
			Inline: true,
		})
	}

	if payload.HighCount > 0 {
		fields = append(fields, DiscordEmbedField{
			Name:   "🔸 High",
			Value:  fmt.Sprintf("%d", payload.HighCount),
			Inline: true,
		})
	}

	return fields
}

// buildSlackStatsFields Slack için istatistik alanları oluşturur
func (n *Notifier) buildSlackStatsFields(payload NotificationPayload) []SlackField {
	var fields []SlackField

	if payload.SubdomainCount > 0 {
		fields = append(fields, SlackField{
			Title: "📊 Subdomains",
			Value: fmt.Sprintf("%d", payload.SubdomainCount),
			Short: true,
		})
	}

	if payload.LiveHostCount > 0 {
		fields = append(fields, SlackField{
			Title: "🟢 Live Hosts",
			Value: fmt.Sprintf("%d", payload.LiveHostCount),
			Short: true,
		})
	}

	if payload.VulnCount > 0 {
		fields = append(fields, SlackField{
			Title: "🔴 Vulnerabilities",
			Value: fmt.Sprintf("%d", payload.VulnCount),
			Short: true,
		})
	}

	if payload.CriticalCount > 0 {
		fields = append(fields, SlackField{
			Title: "⚠️ Critical",
			Value: fmt.Sprintf("%d", payload.CriticalCount),
			Short: true,
		})
	}

	if payload.HighCount > 0 {
		fields = append(fields, SlackField{
			Title: "🔸 High",
			Value: fmt.Sprintf("%d", payload.HighCount),
			Short: true,
		})
	}

	return fields
}

// validateWebhookURL webhook URL'sinin güvenli olduğunu doğrular (SSRF koruması).
func validateWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("geçersiz webhook URL: %w", err)
	}
	// Sadece HTTPS (ve geliştirme için HTTP) kabul et
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("webhook URL scheme https veya http olmalı, aldığım: %s", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL'de host bulunamadı")
	}
	// İç ağ IP kontrolü
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL iç ağ adreslerine işaret edemez: %s", host)
		}
	}
	// Localhost alias kontrolü
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") || lowerHost == "[::1]" {
		return fmt.Errorf("webhook URL localhost'a işaret edemez: %s", host)
	}
	// Bilinen webhook domain'leri whitelist (Discord + Slack)
	allowed := []string{"discord.com", "discordapp.com", "slack.com", "hooks.slack.com"}
	isAllowed := false
	for _, a := range allowed {
		if lowerHost == a || strings.HasSuffix(lowerHost, "."+a) {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		logger.Warnf("Webhook URL bilinen servis listesinde değil: %s (izin verilenler: %v)", host, allowed)
	}
	return nil
}

// sendWebhook webhook'a generic POST isteği gönderir
func (n *Notifier) sendWebhook(webhookURL string, payload interface{}, platform string) error {
	// SSRF koruması: URL doğrulama
	if err := validateWebhookURL(webhookURL); err != nil {
		return fmt.Errorf("webhook URL doğrulama hatası (%s): %w", platform, err)
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("JSON marshal error: %w", err)
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf("%s webhook hatası: HTTP %d", platform, resp.StatusCode)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	if n.verbose {
		color.Green("[✓] %s notification sent", platform)
	}

	return nil
}

// SendStartNotification tarama başlangıç bildirimi
func (n *Notifier) SendStartNotification(domain string) error {
	return n.SendNotification(NotificationPayload{
		Domain:  domain,
		Status:  "started",
	})
}

// SendPhaseNotification phase tamamlanma bildirimi
func (n *Notifier) SendPhaseNotification(domain, phase, message string, subdomainCount, liveHostCount, vulnCount, criticalCount, highCount int) error {
	return n.SendNotification(NotificationPayload{
		Domain:         domain,
		Phase:          phase,
		Message:        message,
		SubdomainCount: subdomainCount,
		LiveHostCount:  liveHostCount,
		VulnCount:      vulnCount,
		CriticalCount:  criticalCount,
		HighCount:      highCount,
		Status:         "phase_complete",
	})
}

// SendCompleteNotification tarama tamamlanma bildirimi
func (n *Notifier) SendCompleteNotification(domain string, subdomainCount, liveHostCount, vulnCount, criticalCount, highCount int) error {
	return n.SendNotification(NotificationPayload{
		Domain:         domain,
		SubdomainCount: subdomainCount,
		LiveHostCount:  liveHostCount,
		VulnCount:      vulnCount,
		CriticalCount:  criticalCount,
		HighCount:      highCount,
		Status:         "completed",
	})
}

// SendErrorNotification hata bildirimi
func (n *Notifier) SendErrorNotification(domain, message string) error {
	return n.SendNotification(NotificationPayload{
		Domain:  domain,
		Message: message,
		Status:  "error",
	})
}
