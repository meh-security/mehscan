package fixture

func review(value string) {
	cache.Lookup(value)
	local.Fetch(value)
	filesystem.SafeOpen(value)
	sandbox.SafeEval(value)
}

