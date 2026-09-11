package guidance

import "crypto/tls"

func configure() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
