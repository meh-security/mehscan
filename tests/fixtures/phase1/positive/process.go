package fixture

import (
	"context"
	"os/exec"
)

func run(ctx context.Context, command string) {
	exec.Command(command).Run()
	exec.CommandContext(ctx, command, "--version").Run()
}

