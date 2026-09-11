import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'

export default NextAuth({
  providers: [
    CredentialsProvider({
      async authorize(credentials) {
        if (credentials.username === 'admin' && credentials.password === 'fixed-password') {
          return { id: 1, name: 'Administrator' }
        }
        return null
      }
    })
  ],
  session: { strategy: 'jwt' }
})
