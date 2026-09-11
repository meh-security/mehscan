function direct(req: any, pool: any) {
  return pool.query(req.query.direct)
}

function propagated(req: any, pool: any) {
  const query = req.query.propagated
  const alias = query
  return pool.query(alias)
}
