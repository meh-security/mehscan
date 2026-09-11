import crypto from 'node:crypto'

export function checksum (payload: string) {
  return crypto.createHash('md5').update(payload).digest('hex')
}
