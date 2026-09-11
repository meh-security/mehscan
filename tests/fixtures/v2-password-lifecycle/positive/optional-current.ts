import type { Request, Response } from 'express'

export async function changePassword (req: Request, res: Response, user: any) {
  const currentPassword = req.body.current
  if (currentPassword && hash(currentPassword) !== user.password) {
    res.status(401).end()
    return
  }
  await user.update({ password: req.body.newPassword })
}
