import { UserModel } from '../models/user'

export async function StoredProfile({ id }: Props) {
  const user = await UserModel.findOne({ where: { id } })
  const username = user.username
  const code = username.replace(/.*/g, 'fixed')
  return <div>{eval(code)}</div>
}

export function BuiltProfile({ username }: Props) {
  const user = UserModel.build({ username })
  return <div>{eval(user.username)}</div>
}
