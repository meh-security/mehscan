import crypto from 'node:crypto'

export function setPassword (clearTextPassword: string) {
  this.setDataValue('password', crypto.createHash('sha256').update(clearTextPassword).digest('hex'))
}
