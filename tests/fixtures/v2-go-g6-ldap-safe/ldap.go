package directory

import (
	"crypto/tls"
	"fmt"
	"html"
	"net/http"

	ldap "gopkg.in/ldap.v2"
)

type Client struct{ conn *ldap.Conn }

var client Client

func (c *Client) search(filter string) {
	request := ldap.NewSearchRequest("dc=example", 2, 0, 0, 0, false, filter, nil, nil)
	_, _ = c.conn.Search(request)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if values, ok := r.Form["filter"]; ok {
		filter := ldap.EscapeFilter(values[0])
		client.search(filter)
		fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(values[0]))
	}
}

func connect(address string) {
	_, _ = ldap.DialTLS("tcp", address, &tls.Config{MinVersion: tls.VersionTLS12})
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}
