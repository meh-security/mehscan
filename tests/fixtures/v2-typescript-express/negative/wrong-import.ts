import type { Request } from "./transport"

export function unrelated(input: Request) {
  const { body: payload } = input
  return eval(payload.code)
}
