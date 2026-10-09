package processflow

import "os/exec"

func direct(r *Request) {
	exec.Command(r.FormValue("direct")).Run()
}

func propagated(r *Request) {
	command := r.FormValue("propagated")
	alias := command
	exec.Command(alias).Run()
}

func separated(r *Request) {
	exec.Command("tool", r.FormValue("argument")).Run()
}
