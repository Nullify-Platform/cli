package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanStatusJSONRoundTrip(t *testing.T) {
	// The wire representation must remain the same lowercase string after the
	// Status field was changed from *string to the typed *ScanStatus enum.
	input := DASTUpdateExternalScanInput{
		Status: ScanStatusPtr(StatusCompleted),
	}

	out, err := json.Marshal(input)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	require.Equal(t, "completed", got["status"])
}

func TestParseScanStatus(t *testing.T) {
	s, err := ParseScanStatus("completed")
	require.NoError(t, err)
	require.Equal(t, StatusCompleted, s)
	require.Equal(t, "completed", s.String())

	_, err = ParseScanStatus("pending")
	require.Error(t, err)
}
