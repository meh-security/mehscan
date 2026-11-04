import * as fs from 'node:fs'
export function direct(req: any) {
  return fs.readFileSync(req.query.direct)
}

export function propagated(req: any, content: any) {
  const requested = req.query.propagated
  const alias = requested
  return fs.writeFileSync(alias, content)
}

export function canonicalized(req: any, path: any) {
  const canonical = path.resolve(req.query.protected)
  return fs.readFileSync(canonical)
}

export function contained(candidate: string, root: string, path: any) {
  return !path.relative(root, candidate).startsWith("..")
}
