import crypto from 'node:crypto'

export function setPassword (clearTextPassword: string) {
  this.setDataValue('password', crypto.scryptSync(clearTextPassword, crypto.randomBytes(16), 64))
}
