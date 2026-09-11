function safeLookup(pool: any, id: string) {
  return pool.query('SELECT * FROM users WHERE id = $1', [id])
}
