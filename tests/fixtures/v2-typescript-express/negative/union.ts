import type { Request as ExpressRequest } from "express"

interface InternalMessage {
  body: { code: string }
}

export function ambiguous(input: ExpressRequest | InternalMessage) {
  return eval(input.body.code)
}
