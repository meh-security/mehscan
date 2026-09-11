import type { Request } from 'express'

export function applySetting (req: Request, settings: Record<string, unknown>) {
  const key = req.body.key
  settings[key] = req.body.value
}
