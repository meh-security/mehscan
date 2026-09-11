import type { Request } from 'express'

export async function resetPassword (req: Request, user: any, data: any) {
  const answer = req.body.answer
  if (hmac(answer) === data.answer) {
    await user.update({ password: req.body.newPassword })
  }
}
