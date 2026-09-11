package fixture

import "fmt"

func Connections(user, password, host, port string) {
	_ = fmt.Sprintf("host=%s sslmode=disable", host)
	_ = fmt.Sprintf("mongodb://%s:%s@%s:%s", user, password, host, port)
}
