export function direct(req: any, res: any) {
  return res.redirect(req.query.direct)
}

export function propagated(req: any, res: any) {
  const requested = req.query.propagated
  const alias = requested
  return res.redirect(alias)
}

export function parsed(req: any, res: any) {
  const destination = new URL(req.query.parsed)
  return res.redirect(destination.toString())
}

export function validOrigin(destination: string, base: URL) {
  return new URL(destination, base).origin === base.origin
}
