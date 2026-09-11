export function leave(req: any, res: any) {
  const destination = new URL(req.query.next)
  return res.redirect(destination.toString())
}
