package safeeval

func safeLookup(db *DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
