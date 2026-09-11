import express from 'express'

const app = express()

app.get('/api/token', (_request, response) => {
  const token = Math.random().toString(36).substring(7)
  response.json({ token })
})

export function createPasswordResetToken(): string {
  const resetToken = `${Date.now()}-${Math.random()}`
  return resetToken
}

// const authToken = Math.random().toString(36)
