import crypto from 'node:crypto'

export const hash = (data: string) => crypto.createHash('sha512').update(data).digest('hex')
