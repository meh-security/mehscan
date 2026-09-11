const app: any = {}
const hash = (value: string) => value

export const UserFields = {
  password: {
    type: 'string',
    set (clearTextPassword: string) {
      this.setDataValue('password', hash(clearTextPassword))
    }
  }
}

app.post('/api/Users', (req: any, res: any, next: any) => {
  if (req.body.email !== undefined && req.body.password !== undefined) {
    if (req.body.email.length !== 0 && req.body.password.length !== 0) {
      req.body.email = req.body.email.trim()
    } else {
      res.status(400).send('Invalid email/password cannot be empty')
    }
  }
  next()
})

export const passwordRepeat = () => (req: any, _res: any, next: any) => {
  if (req.body.passwordRepeat !== req.body.password) {
    auditMismatch()
  }
  next()
}

export function resetPassword () {
  return async ({ body }: any, res: any) => {
    const data = await SecurityAnswerModel.findOne({ where: { email: body.email } })
    if (hmac(body.answer) === data.answer) {
      const user = await UserModel.findByPk(data.UserId)
      await user.update({ password: body.newPassword })
      res.json({ ok: true })
    }
  }
}

declare const SecurityAnswerModel: any
declare const UserModel: any
declare const hmac: (value: string) => string
declare const auditMismatch: () => void

