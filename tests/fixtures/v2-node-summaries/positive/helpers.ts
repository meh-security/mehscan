import type { Request } from 'express'

export function requestCommand (request: Request) {
  return request.body.command
}
