function direct(req, res) {
  return res.redirect(req.query.direct)
}

function propagated(req, res) {
  const requested = req.query.propagated
  const alias = requested
  return res.redirect(alias)
}

function parsed(req, res) {
  const destination = new URL(req.query.parsed)
  return res.redirect(destination.toString())
}

function validOrigin(destination, base) {
  return new URL(destination, base).origin === base.origin
}
