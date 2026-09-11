import * as security from '../lib/weak'

export function setPassword (clearTextPassword: string) {
  this.setDataValue('password', security.hash(clearTextPassword))
}
