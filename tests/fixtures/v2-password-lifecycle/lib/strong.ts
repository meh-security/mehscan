import bcrypt from 'bcrypt'

export const hashPassword = (data: string) => bcrypt.hash(data, 12)
