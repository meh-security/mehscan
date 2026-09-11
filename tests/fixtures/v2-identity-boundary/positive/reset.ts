export async function resetPassword (req: any, user: any) {
  const token = req.body.token
  if (!verifyResetToken(token)) return
  await user.update({ password: req.body.password })
}

declare function verifyResetToken (token: string): boolean
