type RequestHandler = (input: { body: { code: string } }) => unknown

export const contextual: RequestHandler = incoming => {
  return eval(incoming.body.code)
}
