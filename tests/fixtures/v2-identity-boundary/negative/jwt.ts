import jwt from 'jsonwebtoken'

const privateKey = process.env.JWT_PRIVATE_KEY as string
const publicKey = process.env.JWT_PUBLIC_KEY as string

export function issueAndVerify (payload: object, token: string) {
  const issued = jwt.sign(payload, privateKey, { expiresIn: '15m', algorithm: 'RS256' })
  const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
  return { issued, decoded }
}

export function verifiedIdentity (req: any) {
  const decoded = jwt.verify(req.headers.authorization, publicKey, { algorithms: ['RS256'] })
  return decoded?.data?.id
}
