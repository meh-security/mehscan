package fixture

func review(config *Config) {
	_ = config.Header.Get("X-Trace")
}
