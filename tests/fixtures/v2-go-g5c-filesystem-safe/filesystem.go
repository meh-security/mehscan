package filesystem

import stdos "os"

func exclusiveCreate(path string) {
	_, _ = stdos.OpenFile(path, stdos.O_WRONLY|stdos.O_CREATE|stdos.O_EXCL, 0600)
	_ = stdos.MkdirAll("./private", 0750)
	_ = stdos.Mkdir("./owner", 0700)
}
