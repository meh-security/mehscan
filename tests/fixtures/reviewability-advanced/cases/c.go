package cases

func inspect(r *Request) error {
	requested := r.FormValue("name")
	argument := requested
	return exec.Command("tool", argument).Run()
}
