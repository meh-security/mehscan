package filesystemflow

func direct(r *Request) {
	_, _ = os.Open(r.FormValue("direct"))
}

func propagated(r *Request, content []byte) {
	requested := r.FormValue("propagated")
	alias := requested
	_ = os.WriteFile(alias, content, 0600)
}

func canonicalized(r *Request) {
	canonical := filepath.Clean(r.FormValue("protected"))
	_, _ = os.Open(canonical)
}

func contained(candidate string) bool {
	return filepath.IsLocal(candidate)
}
