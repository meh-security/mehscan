import { getServerSession } from 'next-auth/next'

export default async function account(req, res) {
  const session = await getServerSession(req, res, authOptions)
  if (!session) return res.status(401).json({ error: 'unauthorized' })
  return res.status(200).json({ id: session.user.id })
}
