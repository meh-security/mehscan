package dynamiccodeflow

func direct(r *http.Request) (*plugin.Plugin, error) {
	return plugin.Open(r.FormValue("plugin"))
}

func propagated(r *http.Request) (*plugin.Plugin, error) {
	requested := r.FormValue("plugin")
	alias := requested
	return plugin.Open(alias)
}

func restricted(r *http.Request) (*plugin.Plugin, error) {
	return plugin.Open(filepath.Base(r.FormValue("restricted")))
}
