function direct(req, res) {
  return res.send(req.query.direct)
}

function propagated(req, res) {
  const content = req.query.propagated
  const alias = content
  return res.send(alias)
}

function encoded(req, res, he) {
  const content = he.encode(req.query.encoded)
  return res.send(content)
}
