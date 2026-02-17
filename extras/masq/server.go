package masq

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/extras/v2/correctnet"
)

const (
	cacheSize    = 1000
	cacheTTL     = 5 * time.Minute
	rateLimitReq = 100
	rateLimitWin = 10 * time.Second
	suspiciousUA = "curl|wget|python|go-http|scanner|nikto|nmap"
)

type SiteConfig struct {
	Title       string
	Description string
	Keywords    string
	StaticDir   string
	HidePaths   []string
}

type rateLimitEntry struct {
	count     int
	firstSeen time.Time
}

type cacheEntry struct {
	data      []byte
	timestamp time.Time
}

type MasqTCPServer struct {
	QUICPort      int
	HTTPSPort     int
	Handler       http.Handler
	TLSConfig     *tls.Config
	ForceHTTPS    bool
	SiteConfig    *SiteConfig
	rateLimitMu   sync.Mutex
	rateLimitMap  map[string]*rateLimitEntry
	cacheMu       sync.RWMutex
	cacheMap      map[string]*cacheEntry
}

func NewMasqTCPServer(quicPort, httpsPort int, tlsConfig *tls.Config, siteConfig *SiteConfig) *MasqTCPServer {
	return &MasqTCPServer{
		QUICPort:     quicPort,
		HTTPSPort:    httpsPort,
		TLSConfig:    tlsConfig,
		SiteConfig:   siteConfig,
		rateLimitMap: make(map[string]*rateLimitEntry),
		cacheMap:     make(map[string]*cacheEntry),
	}
}

func (s *MasqTCPServer) ListenAndServeHTTP(addr string) error {
	return correctnet.HTTPListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r)
	}))
}

func (s *MasqTCPServer) ListenAndServeHTTPS(addr string) error {
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.ServeHTTP(w, r)
		}),
		TLSConfig: s.TLSConfig,
	}
	listener, err := correctnet.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return server.ServeTLS(listener, "", "")
}

func (s *MasqTCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.checkRateLimit(r) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if s.isSuspiciousRequest(r) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if s.ForceHTTPS {
		if s.HTTPSPort == 0 || s.HTTPSPort == 443 {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		} else {
			http.Redirect(w, r, fmt.Sprintf("https://%s:%d%s", r.Host, s.HTTPSPort, r.RequestURI), http.StatusMovedPermanently)
		}
		return
	}
	path := r.URL.Path
	if path == "/favicon.ico" {
		s.serveFavicon(w, r)
		return
	}
	if path == "/robots.txt" {
		s.serveRobotsTxt(w, r)
		return
	}
	if s.SiteConfig != nil && s.SiteConfig.StaticDir != "" {
		if s.serveStaticFile(w, r) {
			return
		}
	}
	s.serveDefaultPage(w, r)
}

func (s *MasqTCPServer) checkRateLimit(r *http.Request) bool {
	ip := getClientIP(r)
	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()
	entry, exists := s.rateLimitMap[ip]
	now := time.Now()
	if !exists || now.Sub(entry.firstSeen) > rateLimitWin {
		s.rateLimitMap[ip] = &rateLimitEntry{count: 1, firstSeen: now}
		return true
	}
	if entry.count >= rateLimitReq {
		return false
	}
	entry.count++
	return true
}

func (s *MasqTCPServer) isSuspiciousRequest(r *http.Request) bool {
	ua := r.UserAgent()
	if ua == "" {
		return true
	}
	uaLower := strings.ToLower(ua)
	suspiciousList := strings.Split(suspiciousUA, "|")
	for _, sus := range suspiciousList {
		if strings.Contains(uaLower, strings.ToLower(sus)) {
			return true
		}
	}
	if strings.Contains(r.URL.Path, ".env") ||
		strings.Contains(r.URL.Path, "wp-admin") ||
		strings.Contains(r.URL.Path, "phpmyadmin") ||
		strings.Contains(r.URL.Path, ".git") {
		return true
	}
	return false
}

func (s *MasqTCPServer) serveFavicon(w http.ResponseWriter, r *http.Request) {
	s.cacheMu.RLock()
	entry, exists := s.cacheMap["favicon"]
	s.cacheMu.RUnlock()
	if exists && time.Since(entry.timestamp) < cacheTTL {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(entry.data)
		return
	}
	favicon := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00}
	s.cacheMu.Lock()
	s.cacheMap["favicon"] = &cacheEntry{data: favicon, timestamp: time.Now()}
	s.cacheMu.Unlock()
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(favicon)
}

func (s *MasqTCPServer) serveRobotsTxt(w http.ResponseWriter, r *http.Request) {
	robotsTxt := []byte("User-agent: *\nDisallow: /admin/\nDisallow: /private/\n")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(robotsTxt)
}

func (s *MasqTCPServer) serveStaticFile(w http.ResponseWriter, r *http.Request) bool {
	if s.SiteConfig.StaticDir == "" {
		return false
	}
	path := r.URL.Path
	for _, hidden := range s.SiteConfig.HidePaths {
		if strings.Contains(path, hidden) {
			return false
		}
	}
	http.ServeFile(w, r, s.SiteConfig.StaticDir+path)
	return true
}

func (s *MasqTCPServer) serveDefaultPage(w http.ResponseWriter, r *http.Request) {
	title := "Welcome"
	description := "Welcome to our website"
	if s.SiteConfig != nil {
		if s.SiteConfig.Title != "" {
			title = s.SiteConfig.Title
		}
		if s.SiteConfig.Description != "" {
			description = s.SiteConfig.Description
		}
	}
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="%s">
    <meta name="keywords" content="%s">
    <title>%s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>%s</h1>
        <p>%s</p>
    </div>
</body>
</html>`, description, s.SiteConfig.Keywords, title, title, description)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, s.QUICPort))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

var _ http.ResponseWriter = (*altSvcHijackResponseWriter)(nil)

type altSvcHijackResponseWriter struct {
	Port int
	http.ResponseWriter
}

func (w *altSvcHijackResponseWriter) WriteHeader(statusCode int) {
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.Port))
	w.ResponseWriter.WriteHeader(statusCode)
}

var _ http.Hijacker = (*altSvcHijackResponseWriterHijacker)(nil)

type altSvcHijackResponseWriterHijacker struct {
	altSvcHijackResponseWriter
}

func (w *altSvcHijackResponseWriterHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

func newAltSvcHijackResponseWriter(w http.ResponseWriter, port int) http.ResponseWriter {
	if _, ok := w.(http.Hijacker); ok {
		return &altSvcHijackResponseWriterHijacker{
			altSvcHijackResponseWriter: altSvcHijackResponseWriter{
				Port:           port,
				ResponseWriter: w,
			},
		}
	}
	return &altSvcHijackResponseWriter{
		Port:           port,
		ResponseWriter: w,
	}
}