declare const UserModel: any

async function deleteCreatedUser (userId: number) {
  return await UserModel.destroy({ where: { id: userId } })
}

export async function createSeedUser () {
  const user = await UserModel.create({ email: 'seed@example.test' })
  await deleteCreatedUser(user.id)
}

export async function deleteRequestedUser (userId: number) {
  return await UserModel.destroy({ where: { id: userId } })
}
