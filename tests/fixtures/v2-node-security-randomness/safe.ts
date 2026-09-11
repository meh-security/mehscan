import crypto from 'crypto'
import { randomBytes as secureBytes } from 'node:crypto'

export function createResetToken(): string {
  const resetToken = crypto.randomBytes(32).toString('hex')
  return resetToken
}

export function hashPassword(password: string): string {
  const salt = secureBytes(16)
  return `${salt.toString('hex')}:${password}`
}

export function quotePrice(): number {
  const price = Math.random() * 100
  return price
}
