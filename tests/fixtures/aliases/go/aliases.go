package fixture

import osExec "os/exec"

func review(command string) {
	osExec.Command(command)
}

func shadowed(osExec interface{ Command(string) }, command string) {
	osExec.Command(command)
}
