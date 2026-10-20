package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestLoginCallbackValidation(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	tests := []struct {
		name, query, method string
		status              int
	}{
		{"valid", "session_id=expected&redemption_secret=" + secret, "GET", 200},
		{"wrong session", "session_id=other&redemption_secret=" + secret, "GET", 403},
		{"missing session", "redemption_secret=" + secret, "GET", 403},
		{"legacy missing secret", "session_id=expected", "GET", 400},
		{"short secret", "session_id=expected&redemption_secret=ab", "GET", 400},
		{"long secret", "session_id=expected&redemption_secret=" + secret + "ab", "GET", 400},
		{"uppercase secret", "session_id=expected&redemption_secret=" + strings.ToUpper(secret), "GET", 400},
		{"nonhex secret", "session_id=expected&redemption_secret=" + strings.Repeat("z", 64), "GET", 400},
		{"duplicate secret", "session_id=expected&redemption_secret=" + secret + "&redemption_secret=" + secret, "GET", 400},
		{"duplicate session", "session_id=expected&session_id=expected&redemption_secret=" + secret, "GET", 403},
		{"wrong method", "session_id=expected&redemption_secret=" + secret, "POST", 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callbacks := make(chan cliCallback, 1)
			handler := newLoginCallbackHandler("expected", callbacks)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tt.method, "/callback?"+tt.query, nil))
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d", response.Code, tt.status)
			}
			if tt.status != 200 {
				if len(callbacks) != 0 {
					t.Fatal("invalid callback consumed session")
				}
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/callback?session_id=expected&redemption_secret="+secret, nil))
			}
			select {
			case got := <-callbacks:
				if got.SessionID != "expected" || got.RedemptionSecret != secret {
					t.Fatal("callback did not preserve credentials")
				}
			default:
				t.Fatal("valid callback not delivered")
			}
			if strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "Authenticated Successfully") {
				t.Fatal("callback exposed secret or reported premature success")
			}
		})
	}
}

func TestLoginCallbackDeliveredOnce(t *testing.T) {
	callbacks := make(chan cliCallback, 16)
	handler := newLoginCallbackHandler("expected", callbacks)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/callback?session_id=expected&redemption_secret="+strings.Repeat("a", 64), nil))
		})
	}
	wg.Wait()
	if len(callbacks) != 1 {
		t.Fatalf("delivered %d callbacks", len(callbacks))
	}
}

func TestFetchCLITokenIncludesRedemptionSecret(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/auth/cli/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["session_id"] != "expected" || body["redemption_secret"] != secret {
			t.Error("missing redemption credentials")
		}
		_, _ = w.Write([]byte(`{"access_token":"token","expires_in":60}`))
	})
	result, err := fetchCLIToken(context.Background(), "example.nullify.ai", "expected", secret)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "token" {
		t.Fatal("missing access token")
	}
}
