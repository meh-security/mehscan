export function direct(req: any) {
  return fetch(req.query.direct)
}

export function propagated(req: any) {
  const requested = req.query.propagated
  const alias = requested
  return fetch(alias)
}

export function parsed(req: any) {
  const destination = new URL(req.query.parsed)
  return fetch(destination)
}

export function validScheme(destination: URL) {
  return destination.protocol === "https:"
}
