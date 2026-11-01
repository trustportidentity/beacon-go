package defender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Decision mirrors a firewall decision from the Beacon server.
type Decision struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`  // "ban", "throttle", "challenge", "allow"
	Scope     string    `json:"scope"` // "ip", "range", "user"
	Value     string    `json:"value"` // IP address, CIDR, or username
	ExpiresAt time.Time `json:"expires_at"`
	Scenario  string    `json:"scenario"`
	Reason    string    `json:"reason"`
}

// Config configures the Beacon AI Defender enforcer.
type Config struct {
	ServerURL       string
	APIKey          string
	ServiceName     string
	SyncInterval    time.Duration
	Simulated       bool // Dry-run mode: logs blocks without aborting requests
	BlockStatusCode int  // Default 403 Forbidden
	OnBlocked       func(ip, path, reason string)
}

// Defender provides high-velocity in-memory firewall inspection and real-time decision syncing.
type Defender struct {
	cfg            Config
	mu             sync.RWMutex
	bannedIPs      map[string]*Decision // ip -> decision
	bannedCIDRs    []cidrRule           // parsed subnets
	allowedIPs     map[string]*Decision // ip -> allow decision
	httpClient     *http.Client
	stopChan       chan struct{}
	lastSync       time.Time
	blockedCount   int
	blockedMu      sync.Mutex
	enforcerID     string
	heuristicMatch int
}

type cidrRule struct {
	decision *Decision
	network  *net.IPNet
}

// New initializes a new Defender enforcer.
func New(cfg Config) (*Defender, error) {
	if cfg.ServerURL == "" {
		cfg.ServerURL = "http://localhost:8443"
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	if cfg.BlockStatusCode <= 0 {
		cfg.BlockStatusCode = http.StatusForbidden
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}

	d := &Defender{
		cfg:         cfg,
		bannedIPs:   make(map[string]*Decision),
		bannedCIDRs: make([]cidrRule, 0),
		allowedIPs:  make(map[string]*Decision),
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
		},
		stopChan:   make(chan struct{}),
		enforcerID: fmt.Sprintf("%s-%s-%s", cfg.ServiceName, hostname, uuid.New().String()[:6]),
	}

	// Perform initial startup sync
	if err := d.sync(true); err != nil {
		log.Printf("⚠ [Beacon Defender] Initial decision sync failed: %v (enforcer will continue with local heuristics)", err)
	}

	// Start background sync & heartbeat worker
	go d.syncLoop()

	return d, nil
}

// Close stops the background sync worker and sends a final heartbeat.
func (d *Defender) Close() {
	select {
	case <-d.stopChan:
		return
	default:
		close(d.stopChan)
		d.sendHeartbeat()
	}
}

// CheckIP determines whether a given client IP is blocked.
func (d *Defender) CheckIP(clientIP string) (bool, string) {
	ipStr := strings.TrimSpace(clientIP)
	if ipStr == "" {
		return false, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now()

	// 1. Allowlist takes precedence
	if allow, ok := d.allowedIPs[ipStr]; ok && allow.ExpiresAt.After(now) {
		return false, ""
	}

	// 2. Direct IP ban check (< 100ns)
	if ban, ok := d.bannedIPs[ipStr]; ok && ban.ExpiresAt.After(now) {
		return true, fmt.Sprintf("IP %s banned by Beacon Defender (%s)", ipStr, ban.Scenario)
	}

	// 3. CIDR subnet ban check
	ip := net.ParseIP(ipStr)
	if ip != nil {
		for _, c := range d.bannedCIDRs {
			if c.decision.ExpiresAt.After(now) && c.network.Contains(ip) {
				return true, fmt.Sprintf("IP %s in banned subnet %s (%s)", ipStr, c.network.String(), c.decision.Scenario)
			}
		}
	}

	return false, ""
}

// CheckRequest inspects an incoming HTTP request for both IP bans and immediate attack heuristics.
func (d *Defender) CheckRequest(r *http.Request) (bool, string) {
	clientIP := ExtractIP(r)

	// 1. Check synced decisions
	if blocked, reason := d.CheckIP(clientIP); blocked {
		d.recordBlock(clientIP, r.URL.Path, reason)
		return true, reason
	}

	// 2. Immediate local heuristic inspection (zero network overhead, instant protection)
	pathLower := strings.ToLower(r.URL.Path)
	rawQueryLower := strings.ToLower(r.URL.RawQuery)
	fullTarget := pathLower
	if rawQueryLower != "" {
		fullTarget += "?" + rawQueryLower
	}

	decodedTarget := decodeTarget(fullTarget)

	// Heuristic A: Path Traversal
	if strings.Contains(fullTarget, "../") || strings.Contains(decodedTarget, "../") ||
		strings.Contains(decodedTarget, "..\\") || strings.Contains(pathLower, "/etc/passwd") ||
		strings.Contains(pathLower, "/etc/shadow") || strings.Contains(pathLower, "/win.ini") {
		reason := "Malicious path traversal sequence detected"
		d.recordBlock(clientIP, r.URL.Path, reason)
		return true, reason
	}

	// Heuristic B: SQL Injection patterns in URL / Query
	sqlSignatures := []string{
		"union+select", "union select", "union%20select",
		"or+1=1", "or 1=1", "or%201=1",
		"exec(", "benchmark(", "sleep(",
		"' or '1'='1", "\" or \"1\"=\"1",
	}
	for _, sig := range sqlSignatures {
		if strings.Contains(fullTarget, sig) || strings.Contains(decodedTarget, sig) {
			reason := fmt.Sprintf("SQL injection signature detected (%s)", sig)
			d.recordBlock(clientIP, r.URL.Path, reason)
			return true, reason
		}
	}

	// Heuristic C: Prompt Injection in Headers
	for k, v := range r.Header {
		lowerHdr := strings.ToLower(k + ": " + strings.Join(v, " "))
		if strings.Contains(lowerHdr, "ignore previous instructions") ||
			strings.Contains(lowerHdr, "system prompt override") ||
			strings.Contains(lowerHdr, "you are now in developer mode") {
			reason := "Adversarial prompt injection pattern detected in header"
			d.recordBlock(clientIP, r.URL.Path, reason)
			return true, reason
		}
	}

	return false, ""
}

func (d *Defender) recordBlock(ip, path, reason string) {
	d.blockedMu.Lock()
	d.blockedCount++
	d.blockedMu.Unlock()

	if d.cfg.OnBlocked != nil {
		d.cfg.OnBlocked(ip, path, reason)
	}
}

// ExtractIP retrieves the real client IP using standard reverse proxy headers.
func ExtractIP(r *http.Request) string {
	for _, h := range []string{"CF-Connecting-IP", "True-Client-IP"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" && net.ParseIP(v) != nil {
			return v
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); net.ParseIP(first) != nil {
			return first
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func decodeTarget(s string) string {
	res := s
	if unescaped, err := url.QueryUnescape(res); err == nil {
		res = unescaped
	}
	if unescaped, err := url.PathUnescape(res); err == nil {
		res = unescaped
	}
	return strings.ReplaceAll(res, "+", " ")
}

func (d *Defender) syncLoop() {
	syncTicker := time.NewTicker(d.cfg.SyncInterval)
	defer syncTicker.Stop()

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-d.stopChan:
			return
		case <-syncTicker.C:
			_ = d.sync(false)
		case <-heartbeatTicker.C:
			d.sendHeartbeat()
		}
	}
}

func (d *Defender) sync(startup bool) error {
	reqURL := fmt.Sprintf("%s/v1/defender/stream", d.cfg.ServerURL)
	if startup || d.lastSync.IsZero() {
		reqURL += "?startup=true"
	} else {
		reqURL += fmt.Sprintf("?since=%s", url.QueryEscape(d.lastSync.Format(time.RFC3339)))
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Beacon-Key", d.cfg.APIKey)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("sync returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var streamRes struct {
		Added    []*Decision `json:"added"`
		Deleted  []string    `json:"deleted"`
		SyncTime string      `json:"sync_time"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&streamRes); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Handle deletions
	for _, id := range streamRes.Deleted {
		for ip, ban := range d.bannedIPs {
			if ban.ID == id {
				delete(d.bannedIPs, ip)
			}
		}
		newCidrs := make([]cidrRule, 0, len(d.bannedCIDRs))
		for _, c := range d.bannedCIDRs {
			if c.decision.ID != id {
				newCidrs = append(newCidrs, c)
			}
		}
		d.bannedCIDRs = newCidrs
	}

	// Handle additions
	for _, item := range streamRes.Added {
		if item.ExpiresAt.Before(now) {
			continue
		}
		val := strings.TrimSpace(item.Value)
		if item.Type == "allow" {
			d.allowedIPs[val] = item
		} else if strings.Contains(val, "/") {
			_, netw, err := net.ParseCIDR(val)
			if err == nil {
				d.bannedCIDRs = append(d.bannedCIDRs, cidrRule{decision: item, network: netw})
			}
		} else {
			d.bannedIPs[val] = item
		}
	}

	if streamRes.SyncTime != "" {
		if parsed, err := time.Parse(time.RFC3339, streamRes.SyncTime); err == nil {
			d.lastSync = parsed
		} else {
			d.lastSync = now
		}
	} else {
		d.lastSync = now
	}

	return nil
}

func (d *Defender) sendHeartbeat() {
	d.blockedMu.Lock()
	count := d.blockedCount
	d.blockedCount = 0
	d.blockedMu.Unlock()

	d.mu.RLock()
	cachedBans := len(d.bannedIPs) + len(d.bannedCIDRs)
	d.mu.RUnlock()

	hostname, _ := os.Hostname()
	payload := map[string]any{
		"id":           d.enforcerID,
		"service_name": d.cfg.ServiceName,
		"hostname":     hostname,
		"sdk_version":  "1.2.0",
		"cached_bans":  cachedBans,
		"blocks_count": count,
		"last_sync":    time.Now().Format(time.RFC3339),
	}

	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, d.cfg.ServerURL+"/v1/defender/heartbeat", bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Beacon-Key", d.cfg.APIKey)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := d.httpClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// BannedCount returns the number of active banned IPs and CIDRs currently cached in memory.
func (d *Defender) BannedCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.bannedIPs) + len(d.bannedCIDRs)
}
