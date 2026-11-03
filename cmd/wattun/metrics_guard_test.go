package main

import (
	"net/http/httptest"
	"testing"
)

func TestCrossSiteRequest(t *testing.T) {
	for _, c := range []struct {
		name, fetchSite, origin string
		want                    bool
	}{
		{name: "no browser headers (curl, manager)", want: false},
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
