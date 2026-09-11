package lookalikes

func decode(value string) string {
	return html.UnescapeString(value)
}
