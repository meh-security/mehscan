export async function updateProfile (req: any, user: any) {
  const authenticated = req.cookies.token
  if (!authenticated || !verifyCsrfToken(req.headers['x-csrf-token'])) return
  await user.update({ username: req.body.username })
}

declare function verifyCsrfToken (token: string): boolean
