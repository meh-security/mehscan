import { UserModel } from '../models/user'

export async function renderProfile(id) {
  const user = await UserModel.findByPk(id)
  const username = user.username
  const code = username.replace(/.*/g, 'fixed')
  return eval(code)
}

export function localObject(username) {
  const user = { username }
  return eval(user.username)
}

export async function reassignedModel(id, localUser) {
  let user = await UserModel.findByPk(id)
  user = localUser
  const username = user.username
  return eval(username.substring(2))
}
