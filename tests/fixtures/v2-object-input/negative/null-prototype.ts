import type { Request } from 'express'

export function collectValues (req: Request) {
  const values = Object.create(null)
  values[req.body.key] = req.body.value
  return values
}
