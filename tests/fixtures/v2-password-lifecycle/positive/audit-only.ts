import type { Request } from 'express'

export async function auditedChange (req: Request, user: any) {
  auditPasswordCheck(req.body.current, user.password)
  await user.update({ password: req.body.newPassword })
}
