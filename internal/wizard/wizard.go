package wizard

import (
	"context"
	"fmt"
)

// Step represents a single step in the setup wizard.
type Step struct {
	Name    string
	Check   func(ctx context.Context) bool // returns true if step is already complete
	Execute func(ctx context.Context) error
}

// Run executes the wizard steps in order, skipping completed ones.
func Run(ctx context.Context, steps []Step) error {
	total := len(steps)

	for i, step := range steps {
		fmt.Printf("\n[%d/%d] %s\n", i+1, total, step.Name)

		if step.Check != nil && step.Check(ctx) {
			fmt.Printf("  Already configured. Skipping.\n")
			continue
		}

		if err := step.Execute(ctx); err != nil {
			return fmt.Errorf("step %q failed: %w", step.Name, err)
		}

		fmt.Printf("  Done.\n")
	}

	fmt.Printf("\nSetup complete!\n")
	return nil
}
