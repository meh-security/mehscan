import { hashPassword } from '../lib/strong'

export function setPassword (clearTextPassword: string) {
  this.setDataValue('password', hashPassword(clearTextPassword))
}
