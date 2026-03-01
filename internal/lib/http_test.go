package lib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildQueryString(t *testing.T) {
	tests := []struct {
		name     string
		base     map[string]string
		extra    []string
		contains []string
		empty    bool
	}{
		{
			name:  "empty",
			base:  nil,
			empty: true,
		},
		{
			name:     "base only",
			base:     map[string]string{"orgId": "abc"},
			contains: []string{"orgId=abc"},
		},
		{
			name:     "extra only",
			base:     nil,
			extra:    []string{"severity", "high", "status", "open"},
			contains: []string{"severity=high", "status=open"},
		},
		{
			name:     "skips empty values",
			base:     nil,
			extra:    []string{"severity", "", "status", "open"},
			contains: []string{"status=open"},
		},
		{
			name:     "URL encodes special characters",
			base:     map[string]string{"filter": "a&b=c"},
			contains: []string{"filter=a%26b%3Dc"},
		},
		{
			name:     "URL encodes spaces",
			base:     nil,
			extra:    []string{"repo", "my repo"},
			contains: []string{"repo=my+repo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildQueryString(tt.base, tt.extra...)
			if tt.empty {
				require.Empty(t, result)
				return
			}
			require.True(t, len(result) > 0 && result[0] == '?', "should start with ?")
			for _, s := range tt.contains {
				require.Contains(t, result, s)
			}
		})
	}
}

func TestDoGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/test/path", r.URL.Path)
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()

		body, err := DoGet(context.Background(), srv.Client(), srv.URL, "/test/path")
		require.NoError(t, err)
		require.Equal(t, `{"ok":true}`, body)
	})

	t.Run("non-2xx returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("forbidden"))
		}))
		defer srv.Close()

		_, err := DoGet(context.Background(), srv.Client(), srv.URL, "/fail")
		require.Error(t, err)
		require.Contains(t, err.Error(), "403")
	})
}

func TestBuildQueryStringStartsWithQuestionMark(t *testing.T) {
	result := BuildQueryString(nil, "key", "val")
	require.Equal(t, "?key=val", result)
}
