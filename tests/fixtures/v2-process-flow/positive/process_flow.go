package processflow

func direct(r *Request) {
	exec.Command(r.FormValue("direct"))
}

func propagated(r *Request) {
	command := r.FormValue("propagated")
	alias := command
	exec.Command(alias)
}

func separated(r *Request) {
	exec.Command("tool", r.FormValue("argument"))
}
