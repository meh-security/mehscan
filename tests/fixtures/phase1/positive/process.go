package fixture

import (
	"context"
	"os/exec"
)

func run(ctx context.Context, command string) {
	exec.Command(command)
	exec.CommandContext(ctx, command, "--version")
}

