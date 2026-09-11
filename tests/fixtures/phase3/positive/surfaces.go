package fixture

import (
	"database/sql"
	"net/http"
	"os"
	"plugin"
)

func review(db *sql.DB, query string, url string, path string) {
	db.Query(query)
	http.Get(url)
	os.Open(path)
	os.Create(path)
	plugin.Open(path)
}

