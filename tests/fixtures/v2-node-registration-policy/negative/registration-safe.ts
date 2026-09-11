const app: any = {}
const hash = (value: string) => value

export const UserFields = {
  password: {
    type: 'string',
    validate: { len: [12, 128] },
    set (clearTextPassword: string) {
      this.setDataValue('password', hash(clearTextPassword))
    }
  }
}

app.post('/api/Users', (req: any, res: any, next: any) => {
  if (req.body.email.length === 0 || req.body.password.length === 0) {
    return res.status(400).send('Invalid registration')
  }
  next()
})

export const passwordRepeat = () => (req: any, res: any, next: any) => {
  if (req.body.passwordRepeat !== req.body.password) {
    return res.status(400).send('Passwords do not match')
  }
  next()
}

export async function resetPasswordWithToken (body: any, res: any) {
  const token = await PasswordResetToken.findOne({ where: { tokenHash: hash(body.token) } })
  if (token.expiresAt > Date.now()) {
    const user = await UserModel.findByPk(token.UserId)
    await user.update({ password: body.newPassword })
    res.json({ ok: true })
  }
}

declare const PasswordResetToken: any
declare const UserModel: any

