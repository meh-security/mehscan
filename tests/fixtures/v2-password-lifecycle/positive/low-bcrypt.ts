import bcrypt from 'bcrypt'

export function setPassword (clearTextPassword: string) {
  this.setDataValue('password', bcrypt.hashSync(clearTextPassword, 4))
}
