import type { Request } from 'express'
import { UserModel } from '../model'

export function register (req: Request) {
  return UserModel.create({ email: req.body.email })
}
