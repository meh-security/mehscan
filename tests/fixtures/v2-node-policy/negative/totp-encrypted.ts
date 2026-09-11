export async function setup (secret: string) {
  const userModel: any = await findUser()
  userModel.totpSecret = encrypt(secret)
  await userModel.save()
}

declare function findUser (): Promise<any>
declare function encrypt (value: string): string
