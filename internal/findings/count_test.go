package findings

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCount(t *testing.T) {
	tests := []struct {
		name     string
		opts     SearchOptions
		response string
		want     int
		err      error
		sent     string
	}{
		{
			name:     "the total of the filters is read from one finding",
			opts:     SearchOptions{APITypes: []string{"Code"}, Severity: "high", Status: "open"},
			response: `{"findings":[{}],"total":42,"hasMoreData":true}`,
			want:     42,
			sent:     `{"query":{"isResolved":false,"page":1,"pageSize":1,"severity":["HIGH"],"type":["Code"]}}`,
		},
		{
			name:     "no findings is zero",
			opts:     SearchOptions{APITypes: []string{"Cloud"}},
			response: `{"findings":[],"total":0,"hasMoreData":false}`,
			sent:     `{"query":{"page":1,"pageSize":1,"type":["Cloud"]}}`,
		},
		{name: "a response without findings is unreadable", response: `{"total":3}`, err: ErrUnreadableResponse},
		{name: "missing total", response: `{"findings":[{}]}`, err: ErrUnreadableResponse},
		{name: "null total", response: `{"findings":[],"total":null}`, err: ErrUnreadableResponse},
		{name: "negative total", response: `{"findings":[],"total":-1}`, err: ErrUnreadableResponse},
		{name: "an invalid status sends nothing", opts: SearchOptions{Status: "closed"}, err: ErrInvalidStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTransport{respond: func(int, request) (int, string) { return 200, tt.response }}

			got, err := Count(context.Background(), clientFor(ft), tt.opts)

			require.ErrorIs(t, err, tt.err)
			require.Equal(t, tt.want, got)
			if tt.sent == "" {
				return
			}
			require.Len(t, ft.requests, 1)
			require.Equal(t, "/admin/findings", ft.requests[0].Path)
			require.JSONEq(t, tt.sent, ft.requests[0].Body)
		})
	}
}
