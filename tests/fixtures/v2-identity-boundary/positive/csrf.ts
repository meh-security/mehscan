export async function updateProfile (req: any, user: any) {
  const authenticated = req.cookies.token
  if (!authenticated) return
  await user.update({ username: req.body.username })
}
