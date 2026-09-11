import type { Request } from 'express'

export async function resetPassword (req: Request, user: any) {
  const token = req.body.resetToken
  if (!token || !verifyResetToken(token)) {
    return
  }
  await user.update({ password: req.body.newPassword })
}
