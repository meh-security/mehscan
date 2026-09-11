export function loginCookie (res: any, token: string) {
  res.cookie('token', token, { secure: true, httpOnly: true, sameSite: 'lax' })
}
