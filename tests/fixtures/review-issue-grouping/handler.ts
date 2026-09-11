export function combinedResponse (req: any, res: any) {
  const first = req.query.first
  const second = req.query.second
  res.send(`${first}${second}`)
}
