package terminal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsInteractiveRejectsDevNull(t *testing.T) {
	file, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, file.Close())
	})

	require.False(t, IsInteractive(file))
}
