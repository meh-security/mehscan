package dynamiccodeflow

func execute(r *http.Request) error {
	return safeplugin.Open(r.FormValue("plugin"))
}
