export async function resetPassword (req: any, user: any) {
  const token = req.body.token
  if (!verifyResetToken(token)) return
  await user.update({ password: req.body.password })
  await consumeResetToken(token)
}

declare function verifyResetToken (token: string): boolean
declare function consumeResetToken (token: string): Promise<void>
