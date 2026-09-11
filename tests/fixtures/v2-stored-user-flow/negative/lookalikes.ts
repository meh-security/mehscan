import { UserModel } from '../models/user'

export async function renderProfile(id: number) {
  const user = await UserModel.findByPk(id)
  const username = user.username
  const code = username.replace(/.*/g, 'fixed')
  return eval(code)
}

export function otherField(captcha: Captcha) {
  return eval(captcha.answer)
}
