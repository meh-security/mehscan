package uploadflow

func direct(r *Request, content []byte) {
	_ = os.WriteFile(r.MultipartForm.File["upload"][0].Filename, content, 0600)
}

func propagated(r *Request, content []byte) {
	requested := r.MultipartForm.File["upload"][0].Filename
	alias := requested
	_ = os.WriteFile(alias, content, 0600)
}

func canonicalized(r *Request, content []byte) {
	destination := filepath.Clean(r.MultipartForm.File["upload"][0].Filename)
	_ = os.WriteFile(destination, content, 0600)
}

func validBasename(filename string) bool {
	return filepath.Base(filename) == filename
}
