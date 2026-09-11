import type { Request } from 'express'

export function constantCommand (_request: Request) {
  return 'status'
}

export function conditionalCommand (request: Request, enabled: boolean) {
  if (enabled) return request.body.command
  return 'status'
}

export function firstHop (request: Request) {
  return request.body.command
}

export function secondHop (request: Request) {
  return firstHop(request)
}
