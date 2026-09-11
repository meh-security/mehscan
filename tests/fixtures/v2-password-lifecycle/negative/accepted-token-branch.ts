import type { Request } from 'express'

export async function resetPassword (req: Request, user: any) {
  if (verifyResetToken(req.body.resetToken)) {
    await user.update({ password: req.body.newPassword })
  }
}
