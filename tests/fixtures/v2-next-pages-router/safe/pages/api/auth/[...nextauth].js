import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import { verifyPassword } from '../../../lib/passwords'

export default NextAuth({
  providers: [
    CredentialsProvider({
      async authorize(credentials) {
        const user = await users.findByEmail(credentials.email)
        if (user && await verifyPassword(credentials.password, user.passwordHash)) {
          return { id: user.id, name: user.name }
        }
        return null
      }
    })
  ],
  session: { strategy: 'jwt', maxAge: 3600 }
})
