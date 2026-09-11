function direct(req, pool) {
  return pool.query(req.query.direct)
}

function propagated(req, pool) {
  const query = req.query.propagated
  const alias = query
  return pool.query(alias)
}

function protectedPath(req, pool) {
  return pool.query('SELECT * FROM users WHERE id = $1', [req.query.protected])
}
