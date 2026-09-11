import { UserModel } from '../models/user'

export async function renderProfile(id: number) {
  const user = await UserModel.findByPk(id)
  const username = user.username
  if (username) {
    const code = username?.substring(2, username.length - 1)
    return eval(code)
  }
}
