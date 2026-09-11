package literals

import "os/exec"

const prefix = "safe/"
const command = prefix + "tool"

func review() {
	exec.Command(command)
}
