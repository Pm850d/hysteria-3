package masq

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMasqTCPServer_RateLimit(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{Title: "Test Site"})
	for i := 0; i < rateLimitReq+10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)
		if i < rateLimitReq && w.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i, w.Code)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Rate limit failed: expected 429, got %d", w.Code)
	}
}

func TestMasqTCPServer_SuspiciousUA(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{})
	suspiciousUAs := []string{"curl/7.68.0", "python-requests/2.25.1", "wget/1.20.3", "nikto/2.1.6", ""}
	for _, ua := range suspiciousUAs {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("UA '%s': expected 404, got %d", ua, w.Code)
		}
	}
}

func TestMasqTCPServer_NormalUA(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{Title: "Test Site"})
	normalUAs := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
	}
	for _, ua := range normalUAs {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("UA '%s': expected 200, got %d", ua, w.Code)
		}
	}
}

func TestMasqTCPServer_Favicon(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{})
	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Favicon: expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "image/x-icon" {
		t.Errorf("Favicon: expected image/x-icon, got %s", w.Header().Get("Content-Type"))
	}
}

func TestMasqTCPServer_RobotsTxt(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{})
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Robots.txt: expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("Robots.txt: expected text/plain, got %s", w.Header().Get("Content-Type"))
	}
}

func TestMasqTCPServer_SuspiciousPaths(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{})
	suspiciousPaths := []string{"/.env", "/wp-admin", "/phpmyadmin", "/.git/config"}
	for _, path := range suspiciousPaths {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("Path '%s': expected 404, got %d", path, w.Code)
		}
	}
}

func TestMasqTCPServer_AltSvcHeader(t *testing.T) {
	server := NewMasqTCPServer(8443, 8443, &tls.Config{}, &SiteConfig{})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	altSvc := w.Header().Get("Alt-Svc")
	expected := `h3=":8443"; ma=2592000`
	if altSvc != expected {
		t.Errorf("Alt-Svc: expected '%s', got '%s'", expected, altSvc)
	}
}

func TestMasqTCPServer_SecurityHeaders(t *testing.T) {
	server := NewMasqTCPServer(443, 443, &tls.Config{}, &SiteConfig{})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
	}
	for header, expected := range headers {
		if w.Header().Get(header) != expected {
			t.Errorf("Header '%s': expected '%s', got '%s'", header, expected, w.Header().Get(header))
		}
	}
}