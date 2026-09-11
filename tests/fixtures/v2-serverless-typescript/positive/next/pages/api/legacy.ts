import type { NextApiRequest } from 'next'

export default function handler (request: NextApiRequest) {
  return eval(request.query.code as string)
}
