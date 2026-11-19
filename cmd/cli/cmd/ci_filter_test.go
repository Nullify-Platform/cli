package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOpenFinding(t *testing.T) {
	tests := []struct {
		finding string
		open    bool
	}{
		{`{"id":"b1"}`, true},
		{`{"isLatest":true,"isFixed":false,"isAllowlisted":false,"isArchived":false,"isFalsePositive":false}`, true},
		{`{"isFixed":true}`, false},
		{`{"isAllowlisted":true}`, false},
		{`{"isArchived":true}`, false},
		{`{"isFalsePositive":true}`, false},
		{`{"isLatest":false}`, false},
		{`{"isAllowlisted":null}`, true},
		{`not json`, true},
	}
	for _, tt := range tests {
		t.Run(tt.finding, func(t *testing.T) {
			require.Equal(t, tt.open, isOpenFinding(json.RawMessage(tt.finding)))
		})
	}
}
