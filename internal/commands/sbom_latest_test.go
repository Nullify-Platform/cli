package commands

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/stretchr/testify/require"
)

const sbomTree = `{"tenantId":"t","repositories":[
	{"repositoryId":"r1","projects":[
		{"projectId":"p1","commits":["c1","c2"]},
		{"projectId":"p2","commits":["c3"]},
		{"projectId":"empty","commits":[]}
	]},
	{"repositoryId":"r2","projects":[{"projectId":"p9","commits":["c9"]}]}
]}`

// sbomServers starts a document store that serves /doc/<commit> over https,
// and an API that serves the SBOM tree and answers project reads with a
// presigned URL into the store, recording each project read.
func sbomServers(t *testing.T, store http.HandlerFunc) (*api.Client, *http.Client, *[]string) {
	t.Helper()
	docs := httptest.NewTLSServer(store)
	t.Cleanup(docs.Close)

	var reads []string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/context/sboms/tree":
			_, _ = fmt.Fprint(w, sbomTree)
		case strings.HasPrefix(r.URL.Path, "/context/sboms/repository/") && strings.Contains(r.URL.Path, "/project/"):
			q := r.URL.Query()
			reads = append(reads, fmt.Sprintf("%s from=%s until=%s preferUrl=%s",
				r.URL.Path, q.Get("fromCommit"), q.Get("untilCommit"), q.Get("preferUrl")))
			commit := q.Get("fromCommit")
			_, _ = fmt.Fprintf(w, `{"sboms":[],"urls":[{"commitSha":%q,"url":%q}]}`, commit, docs.URL+"/doc/"+commit)
		default:
			t.Errorf("unexpected API request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(apiSrv.Close)

	c := api.NewClient("acme.nullify.ai", "token", nil, api.WithHTTPClient(apiSrv.Client()))
	c.BaseURL = apiSrv.URL
	return c, docs.Client(), &reads
}

// storedSBOM serves a stored document, which carries no commit SHA, and
// fails the test if a request carries credentials.
func storedSBOM(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("document request carried an Authorization header")
		}
		ecosystem := strings.TrimPrefix(r.URL.Path, "/doc/")
		_, _ = fmt.Fprintf(w, `{"commitSha":"","commitTimestamp":"2026-11-01T00:00:00Z","detectedEcosystems":[%q]}`, ecosystem)
	}
}

func TestLatestSBOMsForOneProject(t *testing.T) {
	c, docs, reads := sbomServers(t, storedSBOM(t))

	got, err := LatestSBOMs(context.Background(), c, docs, "r1", "p1")
	require.NoError(t, err)
	require.Equal(t, []string{"/context/sboms/repository/r1/project/p1 from=c2 until=c2 preferUrl=true"}, *reads)
	require.Len(t, got.Sboms, 1)
	require.Equal(t, "c2", got.Sboms[0].CommitSha)
	require.Equal(t, []string{"c2"}, got.Sboms[0].DetectedEcosystems)
}

func TestLatestSBOMsForEveryProject(t *testing.T) {
	c, docs, reads := sbomServers(t, storedSBOM(t))

	got, err := LatestSBOMs(context.Background(), c, docs, "r1", "")
	require.NoError(t, err)
	require.Equal(t, []string{
		"/context/sboms/repository/r1/project/p1 from=c2 until=c2 preferUrl=true",
		"/context/sboms/repository/r1/project/p2 from=c3 until=c3 preferUrl=true",
	}, *reads)
	require.Len(t, got.Sboms, 2)
	require.Equal(t, "c2", got.Sboms[0].CommitSha)
	require.Equal(t, "c3", got.Sboms[1].CommitSha)
}

func TestLatestSBOMsInlineAnswer(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/context/sboms/tree" {
			_, _ = fmt.Fprint(w, sbomTree)
			return
		}
		_, _ = fmt.Fprint(w, `{"sboms":[{"commitSha":"c3","commitTimestamp":"2026-11-01T00:00:00Z"}]}`)
	}))
	t.Cleanup(apiSrv.Close)
	c := api.NewClient("acme.nullify.ai", "token", nil, api.WithHTTPClient(apiSrv.Client()))
	c.BaseURL = apiSrv.URL

	got, err := LatestSBOMs(context.Background(), c, http.DefaultClient, "r1", "p2")
	require.NoError(t, err)
	require.Len(t, got.Sboms, 1)
	require.Equal(t, "c3", got.Sboms[0].CommitSha)
}

func TestLatestSBOMsTreeErrors(t *testing.T) {
	tests := []struct {
		name, repo, project, want string
	}{
		{name: "unknown repository", repo: "nope", want: "no SBOMs found for repository nope"},
		{name: "unknown project", repo: "r1", project: "nope", want: "repository r1, project nope not found in SBOM tree"},
		{name: "project without SBOMs", repo: "r1", project: "empty", want: "no SBOMs found for repository r1, project empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, docs, reads := sbomServers(t, storedSBOM(t))
			_, err := LatestSBOMs(context.Background(), c, docs, tt.repo, tt.project)
			require.ErrorContains(t, err, tt.want)
			require.Empty(t, *reads)
		})
	}
}

func TestLatestSBOMsDocumentErrors(t *testing.T) {
	tests := []struct {
		name  string
		store http.HandlerFunc
		want  string
	}{
		{
			name:  "store refuses",
			store: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "expired", http.StatusForbidden) },
			want:  "403",
		},
		{
			name:  "not JSON",
			store: func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "<Error/>") },
			want:  "decode SBOM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, docs, _ := sbomServers(t, tt.store)
			_, err := LatestSBOMs(context.Background(), c, docs, "r1", "p1")
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestDownloadSBOMRefusesANonHTTPSURL(t *testing.T) {
	_, err := downloadSBOM(context.Background(), http.DefaultClient, "http://bucket.example/doc")
	require.ErrorContains(t, err, "https")
}
