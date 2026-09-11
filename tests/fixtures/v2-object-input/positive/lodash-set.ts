import type { Request } from 'express'
import _ from 'lodash'

export function applySetting (req: Request, settings: Record<string, unknown>) {
  _.set(settings, req.body.path, req.body.value)
}
