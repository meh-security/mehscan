package filesystem

import "os"

func unsafeCreate(path string) {
	_, _ = os.Create(path)
	_ = os.MkdirAll("./shared", 0777)
	_ = os.Mkdir("./also-shared", 0o7_7_7)
}
