function safeLookup(pool, id) {
  return pool.query('SELECT * FROM users WHERE id = $1', [id])
}
