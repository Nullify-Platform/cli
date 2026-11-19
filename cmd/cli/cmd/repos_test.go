package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/stretchr/testify/require"
)

// testAPIClient returns an API client that sends every request to handler.
func testAPIClient(t *testing.T, handler http.HandlerFunc) *api.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := api.NewClient("acme.nullify.ai", "token", nil, api.WithHTTPClient(srv.Client()))
	c.BaseURL = srv.URL
	return c
}

func TestListAllRepositoriesFollowsNextToken(t *testing.T) {
	pages := map[string]string{
		"":   `{"repositories":[{"id":"c1","name":"api"},{"id":"c2","name":"web"}],"repositoryIds":{"c1":"r1","c2":"r2"},"nextToken":"t1","numItems":2,"version":"1"}`,
		"t1": `{"repositories":[{"id":"c3","name":"worker"}],"repositoryIds":{"c3":"r3"},"nextToken":"","numItems":1,"version":"1"}`,
	}
	var tokens []string
	c := testAPIClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/context/repositories", r.URL.Path)
		token := r.URL.Query().Get("nextToken")
		tokens = append(tokens, token)
		_, _ = fmt.Fprint(w, pages[token])
	})

	got, err := listAllRepositories(context.Background(), c)
	require.NoError(t, err)
	require.Equal(t, []string{"", "t1"}, tokens)
	require.Len(t, got.Repositories, 3)
	require.Equal(t, "worker", *got.Repositories[2].Name)
	require.Equal(t, map[string]string{"c1": "r1", "c2": "r2", "c3": "r3"}, got.RepositoryIds)
	require.Equal(t, 3, got.NumItems)
	require.Empty(t, got.NextToken)
}

func TestListAllRepositoriesSinglePage(t *testing.T) {
	calls := 0
	c := testAPIClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"repositories":[],"nextToken":"","numItems":0}`)
	})

	got, err := listAllRepositories(context.Background(), c)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Empty(t, got.Repositories)
	require.Equal(t, 0, got.NumItems)
}

func TestListAllRepositoriesStopsOnARepeatedToken(t *testing.T) {
	calls := 0
	c := testAPIClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"repositories":[{"id":"c1"}],"nextToken":"same","numItems":1}`)
	})

	_, err := listAllRepositories(context.Background(), c)
	require.ErrorContains(t, err, "repeated")
	require.Equal(t, 2, calls)
}

func TestListAllRepositoriesReturnsAPageError(t *testing.T) {
	c := testAPIClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("nextToken") == "t1" {
			http.Error(w, `{"message":"invalid cursor"}`, http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"repositories":[{"id":"c1"}],"nextToken":"t1","numItems":1}`)
	})

	_, err := listAllRepositories(context.Background(), c)
	require.Error(t, err)
}
