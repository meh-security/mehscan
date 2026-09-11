package fixture

import "database/sql"

func review(db *sql.DB, query string, userID string) {
	_, _ = db.Query(query, userID)
}
