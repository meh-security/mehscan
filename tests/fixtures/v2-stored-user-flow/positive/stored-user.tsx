import { UserModel } from '../models/user'

export async function StoredProfile({ id }: Props) {
  const user = await UserModel.findOne({ where: { id } })
  const username = user.username
  if (username) {
    const code = username.slice(2, username.length - 1)
    return <div>{eval(code)}</div>
  }
  return <div />
}
