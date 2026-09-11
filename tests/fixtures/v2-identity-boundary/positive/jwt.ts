import jwt from 'jsonwebtoken'

const privateKey = '-----BEGIN RSA PRIVATE KEY-----long-test-key-material-for-a-regression-fixture-----END RSA PRIVATE KEY-----'

export function issueAndVerify (payload: object, token: string) {
  const issued = jwt.sign(payload, privateKey)
  const decoded = jwt.verify(token, privateKey)
  return { issued, decoded }
}

export function unverifiedIdentity (req: any) {
  const decoded = jwt.decode(req.headers.authorization)
  return decoded?.data?.id
}
