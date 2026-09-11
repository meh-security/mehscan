export async function setup (secret: string) {
  const userModel: any = await findUser()
  userModel.totpSecret = secret
  await userModel.save()
}

declare function findUser (): Promise<any>
