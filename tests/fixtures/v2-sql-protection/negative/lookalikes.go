package fixture

import "database/sql"

func review(db *sql.DB, query string) {
	_, _ = db.Query(query)
}
