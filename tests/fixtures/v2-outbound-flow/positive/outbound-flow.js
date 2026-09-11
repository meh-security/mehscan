function direct(req) {
  return fetch(req.query.direct)
}

function propagated(req) {
  const requested = req.query.propagated
  const alias = requested
  return fetch(alias)
}

function parsed(req) {
  const destination = new URL(req.query.parsed)
  return fetch(destination)
}

function validScheme(destination) {
  return destination.protocol === "https:"
}
