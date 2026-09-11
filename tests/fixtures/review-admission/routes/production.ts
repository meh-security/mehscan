export function productionHandler (req: any, res: any) {
  res.send(req.query.first)
  return res.send(req.query.second)
}

export function fixedHtmlResponse (res: any) {
  res.send('A fixed response message')
}

export function unresolvedHtmlResponse (res: any, content: unknown) {
  res.send(content)
}
