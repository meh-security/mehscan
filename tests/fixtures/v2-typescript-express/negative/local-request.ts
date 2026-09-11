interface Request {
  body: { code: string }
}

export function localShape(input: Request) {
  return eval(input.body.code)
}
