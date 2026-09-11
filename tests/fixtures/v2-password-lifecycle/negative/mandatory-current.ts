import type { Request } from 'express'

export async function changePassword (req: Request, user: any) {
  const currentPassword = req.body.current
  if (!currentPassword || hash(currentPassword) !== user.password) {
    return
  }
  await user.update({ password: req.body.newPassword })
}
