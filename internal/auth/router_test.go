package auth

import "testing"

func TestIsRouterHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"nullify.ai", true},
		{"api.nullify.ai", true},
		{"app.nullify.ai", true},
		{"https://app.nullify.ai/dashboard", true},
		{"HTTPS://API.NULLIFY.AI", true},
		{" nullify.ai ", true},
		{"acme.nullify.ai", false},
		{"api.acme.nullify.ai", false},
		{"app.acme.nullify.ai", false},
		{"nullify.ai.evil.com", false},
		{"evilnullify.ai", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsRouterHost(tt.host); got != tt.want {
				t.Errorf("IsRouterHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestDataHostFromBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
		wantErr bool
	}{
		{name: "tenant api origin", baseURL: "https://api.acme.nullify.ai", want: "acme.nullify.ai"},
		{name: "trailing slash", baseURL: "https://api.acme.nullify.ai/", want: "acme.nullify.ai"},
		{name: "hyphen and digits", baseURL: "https://api.acme-2.nullify.ai", want: "acme-2.nullify.ai"},
		{name: "http", baseURL: "http://api.acme.nullify.ai", wantErr: true},
		{name: "userinfo", baseURL: "https://user:pass@api.acme.nullify.ai", wantErr: true},
		{name: "port", baseURL: "https://api.acme.nullify.ai:8443", wantErr: true},
		{name: "explicit https port", baseURL: "https://api.acme.nullify.ai:443", wantErr: true},
		{name: "path", baseURL: "https://api.acme.nullify.ai/v1", wantErr: true},
		{name: "query", baseURL: "https://api.acme.nullify.ai?x=1", wantErr: true},
		{name: "empty query", baseURL: "https://api.acme.nullify.ai?", wantErr: true},
		{name: "fragment", baseURL: "https://api.acme.nullify.ai#x", wantErr: true},
		{name: "uppercase", baseURL: "https://API.ACME.NULLIFY.AI", wantErr: true},
		{name: "trailing dot", baseURL: "https://api.acme.nullify.ai.", wantErr: true},
		{name: "router host", baseURL: "https://api.nullify.ai", wantErr: true},
		{name: "app host", baseURL: "https://api.app.nullify.ai", wantErr: true},
		{name: "no api prefix", baseURL: "https://acme.nullify.ai", wantErr: true},
		{name: "nested label", baseURL: "https://api.a.b.nullify.ai", wantErr: true},
		{name: "leading hyphen", baseURL: "https://api.-acme.nullify.ai", wantErr: true},
		{name: "not nullify", baseURL: "https://api.acme.example.com", wantErr: true},
		{name: "nullify lookalike", baseURL: "https://api.acme.nullify.ai.evil.com", wantErr: true},
		{name: "empty", baseURL: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dataHostFromBaseURL(tt.baseURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("dataHostFromBaseURL(%q) = %q, want an error", tt.baseURL, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("dataHostFromBaseURL(%q): %v", tt.baseURL, err)
			}
			if got != tt.want {
				t.Errorf("dataHostFromBaseURL(%q) = %q, want %q", tt.baseURL, got, tt.want)
			}
		})
	}
}
