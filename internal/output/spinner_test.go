package output

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSpinnerStopWaitsForWriter(t *testing.T) {
	var output bytes.Buffer
	spinner := newSpinner("working", false, true, &output)

	time.Sleep(100 * time.Millisecond)
	spinner.Stop()
	written := output.String()
	time.Sleep(100 * time.Millisecond)

	require.NotEmpty(t, written)
	require.Equal(t, written, output.String())
}

func TestSilentSpinnerCanStopMoreThanOnce(t *testing.T) {
	spinner := newSpinner("working", false, false, &bytes.Buffer{})

	spinner.Stop()
	spinner.Stop()
}
