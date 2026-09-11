import crypto from 'node:crypto'

export function setPassword (clearTextPassword: string) {
  this.setDataValue('password', crypto.pbkdf2Sync(clearTextPassword, 'shared-salt', 1000, 32, 'sha256'))
}
