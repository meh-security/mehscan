import type { RequestHandler as ExpressHandler } from "express"

export const contextual: ExpressHandler = (incoming, response) => {
  return response.send(eval(incoming.body.code))
}
