export async function updateProfile (req: any, user: any) {
  const bearer = req.headers.authorization
  if (!bearer) return
  await user.update({ username: req.body.username })
}
