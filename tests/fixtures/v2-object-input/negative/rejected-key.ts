import type { Request } from 'express'

export function applySetting (req: Request, settings: Record<string, unknown>) {
  const key = req.body.key
  if (['__proto__', 'prototype', 'constructor'].includes(key)) {
    return
  }
  settings[key] = req.body.value
}
