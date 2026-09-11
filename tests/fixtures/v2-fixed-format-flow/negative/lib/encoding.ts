import crypto from 'node:crypto'

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('base64')
