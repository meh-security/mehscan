package lookalikes

func run(helper Helper, destination string) bool {
	return helper.IsLocal(destination)
}
