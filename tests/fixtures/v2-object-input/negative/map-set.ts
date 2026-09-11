import type { Request } from 'express'

export function collectValues (req: Request, values: Map<string, unknown>) {
  values.set(req.body.key, req.body.value)
}
