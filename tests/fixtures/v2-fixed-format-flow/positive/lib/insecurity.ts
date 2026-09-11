import crypto from 'node:crypto'

export const hash = (data: string) => crypto.createHash('sha256').update(data).digest('hex')
