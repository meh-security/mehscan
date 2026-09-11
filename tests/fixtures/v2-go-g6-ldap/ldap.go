package directory

import (
	"fmt"
	"net/http"

	directory "gopkg.in/ldap.v2"
)

type Client struct{ conn *directory.Conn }
type Config struct{ BindPassword string }
type Logger struct{}

var client Client
var logger Logger

func (Logger) Debug(value string) {}

func (c *Client) search(filter string) {
	request := directory.NewSearchRequest("dc=example", 2, 0, 0, 0, false, filter, nil, nil)
	_, _ = c.conn.Search(request)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if values, ok := r.Form["filter"]; ok {
		filter := values[0]
		client.search(filter)
		fmt.Fprintf(w, "<p>%s</p>", filter)
	}
}

func splitBranchHandler(w http.ResponseWriter, r *http.Request) {
	var filter, input string
	if values, ok := r.Form["filter"]; ok {
		input = values[0]
	} else {
		input = "*"
	}
	filter = fmt.Sprintf("(cn=%s)", input)
	if filter != "" {
		client.search(filter)
	}
}

func renderEntry(w http.ResponseWriter, entry *directory.Entry) {
	fmt.Fprintf(w, "<h2>%s</h2>", entry.DN)
}

func connect(address string, cfg Config) {
	_, _ = directory.Dial("tcp", address)
	logger.Debug(fmt.Sprintf("password=%s", cfg.BindPassword))
}
