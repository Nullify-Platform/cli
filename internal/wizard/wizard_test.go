package wizard

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunSkipsCompletedSteps(t *testing.T) {
	executedSteps := []string{}

	steps := []Step{
		{
			Name:  "already done",
			Check: func(ctx context.Context) bool { return true },
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "already done")
				return nil
			},
		},
		{
			Name:  "needs work",
			Check: func(ctx context.Context) bool { return false },
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "needs work")
				return nil
			},
		},
	}

	err := Run(context.Background(), steps)
	require.NoError(t, err)
	require.Equal(t, []string{"needs work"}, executedSteps)
}

func TestRunNilCheckAlwaysExecutes(t *testing.T) {
	executed := false

	steps := []Step{
		{
			Name:  "no check",
			Check: nil,
			Execute: func(ctx context.Context) error {
				executed = true
				return nil
			},
		},
	}

	err := Run(context.Background(), steps)
	require.NoError(t, err)
	require.True(t, executed)
}

func TestRunStopsOnError(t *testing.T) {
	executedSteps := []string{}

	steps := []Step{
		{
			Name: "fails",
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "fails")
				return context.Canceled
			},
		},
		{
			Name: "should not run",
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "should not run")
				return nil
			},
		},
	}

	err := Run(context.Background(), steps)
	require.Error(t, err)
	require.Equal(t, []string{"fails"}, executedSteps)
}
