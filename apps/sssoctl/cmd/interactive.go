package cmd

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// noInteractive disables every prompt and TUI. When set, commands fail with a
// list of the parameters they would otherwise have asked for. It can also be
// enabled with SSOCTL_NO_INTERACTIVE=1 or by running with a non-TTY stdin.
var noInteractive bool

// interactive reports whether the CLI may prompt the user.
func interactive() bool {
	if noInteractive {
		return false
	}
	if v := os.Getenv("SSOCTL_NO_INTERACTIVE"); v == "1" || v == "true" {
		return false
	}
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// requireInteractive returns an actionable error when a command needs a human
// but interactive mode is disabled. missing lists the flags that would have
// been prompted for.
func requireInteractive(feature string, missing ...string) error {
	if interactive() {
		return nil
	}
	if len(missing) == 0 {
		return fmt.Errorf("%s requires an interactive terminal (pass --no-interactive to disable prompts)", feature)
	}
	return fmt.Errorf("%s requires the following parameters in non-interactive mode: %v", feature, missing)
}

// errCancelled is returned by prompts and wizards when the user aborts.
var errCancelled = errors.New("cancelled")
