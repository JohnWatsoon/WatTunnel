package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCrossSiteRequest(t *testing.T) {
	for _, c := range []struct {
		name, fetchSite, origin, host string
		want                          bool
	}{
		{name: "no browser headers (curl, manager)", want: false},
		{name: "localhost host", host: "localhost:19700", want: false},
		{name: "loopback v6 host", host: "[::1]:19700", want: false},
		{name: "loopback v6 host without port", host: "[::1]", want: false},
		{name: "host without port", host: "127.0.0.1", want: false},
		{name: "DNS-rebinding host", host: "evil.example:19700", fetchSite: "same-origin", want: true},
		{name: "LAN host", host: "192.168.1.5:19700", want: true},
		{name: "unspecified host (hand-edited metrics: 0.0.0.0)", host: "0.0.0.0:19700", want: false},
		{name: "empty host", host: "-", want: true},
		{name: "same-origin page", fetchSite: "same-origin", want: false},
		{name: "direct navigation", fetchSite: "none", want: false},
		{name: "cross-site page", fetchSite: "cross-site", want: true},
		{name: "same-site page", fetchSite: "same-site", want: true},
		{name: "foreign origin", origin: "http://evil.example", want: true},
		{name: "loopback v4 origin", origin: "http://127.0.0.1:19700", want: false},
		{name: "localhost origin", origin: "http://localhost:19700", want: false},
		{name: "loopback v6 origin", origin: "http://[::1]:19700", want: false},
		{name: "opaque origin", origin: "null", want: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/stats", nil)
			r.Host = "127.0.0.1:19700"
			if c.host == "-" {
				r.Host = ""
			} else if c.host != "" {
				r.Host = c.host
			}
			if c.fetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", c.fetchSite)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := crossSiteRequest(r); got != c.want {
				t.Errorf("crossSiteRequest(Sec-Fetch-Site=%q, Origin=%q) = %v, want %v", c.fetchSite, c.origin, got, c.want)
			}
		})
	}
}

func TestGuard(t *testing.T) {
	for _, c := range []struct {
		name, fetchSite, origin string
		want                    int
	}{
		{name: "cross-site page", fetchSite: "cross-site", want: http.StatusForbidden},
		{name: "foreign origin", origin: "https://evil.example", want: http.StatusForbidden},
		{name: "no browser headers", want: http.StatusNoContent},
		{name: "direct navigation", fetchSite: "none", want: http.StatusNoContent},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/stats", nil)
			r.Host = "127.0.0.1:19700"
			if c.fetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", c.fetchSite)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			w := httptest.NewRecorder()
			guard(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })(w, r)
			if w.Code != c.want {
				t.Errorf("guard(Sec-Fetch-Site=%q, Origin=%q) = %d, want %d", c.fetchSite, c.origin, w.Code, c.want)
			}
		})
	}
}
