package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/apierror"
)

func TestClientDo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header, got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	}

	result, err := client.do(context.Background(), "GET", server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != `{"status":"ok"}` {
		t.Errorf("result = %q, want %q", string(result), `{"status":"ok"}`)
	}
}

func TestClientDo_4xxError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	}

	_, err := client.do(context.Background(), "GET", server.URL+"/missing", nil)
	if err == nil {
		t.Fatal("expected error for 404")
	}

	var apiErr *apierror.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apierror.APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusNotFound)
	}
	if !apiErr.IsNotFound() {
		t.Error("expected IsNotFound() to be true")
	}
	if apiErr.Message != "not found" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "not found")
	}
}

func TestClientDo_5xxError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	}

	_, err := client.do(context.Background(), "GET", server.URL+"/error", nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}

	var apiErr *apierror.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apierror.APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusInternalServerError)
	}
}

func TestHTTPTimeout(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		t.Setenv("NULLIFY_HTTP_TIMEOUT", "")
		if got := httpTimeout(); got != defaultTimeout {
			t.Errorf("httpTimeout() = %v, want %v", got, defaultTimeout)
		}
	})

	t.Run("overrides from env", func(t *testing.T) {
		t.Setenv("NULLIFY_HTTP_TIMEOUT", "120s")
		if got := httpTimeout(); got != 120*time.Second {
			t.Errorf("httpTimeout() = %v, want %v", got, 120*time.Second)
		}
	})

	t.Run("falls back to default on invalid", func(t *testing.T) {
		t.Setenv("NULLIFY_HTTP_TIMEOUT", "not-a-duration")
		if got := httpTimeout(); got != defaultTimeout {
			t.Errorf("httpTimeout() = %v, want %v", got, defaultTimeout)
		}
	})

	t.Run("falls back to default on non-positive", func(t *testing.T) {
		t.Setenv("NULLIFY_HTTP_TIMEOUT", "0s")
		if got := httpTimeout(); got != defaultTimeout {
			t.Errorf("httpTimeout() = %v, want %v", got, defaultTimeout)
		}
	})
}

func TestNewClient_DefaultsToRetryingClient(t *testing.T) {
	c := NewClient("example.com", "tok", nil)
	if c.HTTPClient == nil {
		t.Fatal("expected default HTTPClient to be non-nil")
	}
	if c.HTTPClient.Transport == nil {
		t.Fatal("expected default HTTPClient.Transport to be non-nil (retry transport)")
	}
	if c.HTTPClient.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.HTTPClient.Timeout, defaultTimeout)
	}
	if c.BaseURL != "https://api.example.com" {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, "https://api.example.com")
	}
}

func TestNewClient_WithHTTPClientOverride(t *testing.T) {
	custom := &http.Client{}
	c := NewClient("example.com", "tok", nil, WithHTTPClient(custom))
	if c.HTTPClient != custom {
		t.Error("expected WithHTTPClient to override the default client")
	}
}
