package client

import (
	"errors"
	"testing"
)

func TestNewRefreshingHTTPClientFetchesInitialToken(t *testing.T) {
	calls := 0
	hc, err := NewRefreshingHTTPClient("acme.nullify.ai", func() (string, error) {
		calls++
		return "tok", nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if hc == nil || hc.Transport == nil {
		t.Fatal("expected an http client with a transport")
	}
	if calls != 1 {
		t.Errorf("token provider calls = %d, want 1 (initial fetch)", calls)
	}
}

func TestNewRefreshingHTTPClientFailsFastOnTokenError(t *testing.T) {
	_, err := NewRefreshingHTTPClient("acme.nullify.ai", func() (string, error) {
		return "", errors.New("no creds")
	})
	if err == nil {
		t.Fatal("expected error when initial token fetch fails")
	}
}
