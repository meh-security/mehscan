import type { VercelRequest as Request } from '@vercel/node'

export default function handler (incoming: Request) {
  const { body: payload } = incoming
  return eval(payload.code)
}
