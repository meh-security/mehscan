import type { Request } from 'express'

function direct(req: any, res: any) {
  return res.redirect(req.query.direct)
}

function propagated(req: any, res: any) {
  const requested = req.query.propagated
  const alias = requested
  return res.redirect(alias)
}

function parsed(req: any, res: any) {
  const destination = new URL(req.query.parsed)
  return res.redirect(destination.toString())
}

function validOrigin(destination: string, base: URL) {
  return new URL(destination, base).origin === base.origin
}

function guarded({ query }: Request, res: any, isAllowed: (value: string) => boolean) {
  const destination = query.guarded
  if (isAllowed(destination)) {
    return res.redirect(destination)
  }
}
