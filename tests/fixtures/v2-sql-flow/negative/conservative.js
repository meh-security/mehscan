function reassignmentKill(req, pool) {
  let query = req.query.reassigned
  query = 'SELECT 1'
  return pool.query(query)
}

function branchAssignment(req, pool, enabled) {
  let query = 'SELECT 1'
  if (enabled) {
    query = req.query.branch
  }
  return pool.query(query)
}

function loopMutation(req, pool, values) {
  let query = req.query.loop
  for (const value of values) {
    query = value
  }
  return pool.query(query)
}

function fieldFlow(req, pool) {
  this.query = req.query.field
  return pool.query(this.query)
}

function sourceFunction(req) {
  const query = req.query.crossFunction
  return query
}

function sinkFunction(pool) {
  const query = 'SELECT 1'
  return pool.query(query)
}

function branchSink(req, pool, enabled) {
  const query = req.query.branchSink
  if (enabled) {
    return pool.query(query)
  }
}

function tooManyAliases(req, pool) {
  const first = req.query.deep
  const second = first
  const third = second
  const fourth = third
  const fifth = fourth
  const sixth = fifth
  return pool.query(sixth)
}
