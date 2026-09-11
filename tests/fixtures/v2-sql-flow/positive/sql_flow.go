package sqlflow

func direct(r *Request, db *DB) {
	db.Query(r.URL.Query().Get("direct"))
}

func propagated(r *Request, db *DB) {
	query := r.URL.Query().Get("propagated")
	alias := query
	db.Query(alias)
}
