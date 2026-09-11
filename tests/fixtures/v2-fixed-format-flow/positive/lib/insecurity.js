import crypto from 'node:crypto'

export const hash = (data) => crypto.createHash('md5').update(data).digest('hex')
