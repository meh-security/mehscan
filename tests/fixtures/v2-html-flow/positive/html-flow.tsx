export function direct(req: any, res: any) {
  return res.send(req.query.direct)
}

export function propagated(req: any, res: any) {
  const content = req.query.propagated
  const alias = content
  return res.send(alias)
}

export function encoded(req: any, res: any, he: any) {
  const content = he.encode(req.query.encoded)
  return res.send(content)
}
