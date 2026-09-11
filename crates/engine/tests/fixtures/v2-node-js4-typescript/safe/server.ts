import * as express from 'express'
import * as yaml from 'js-yaml'
import * as jwt from 'jsonwebtoken'

interface User {
  id: number
  password: string
  role: string
  ownerId: number
}

const users: User[] = []
const app = express()
const axios = { default: { get: (url: string) => ({ data: url }) } }
const _ = { merge: (target: object, source: object) => ({ target, source }) }
const requireAdmin = (_req: unknown, _res: unknown, next: () => void) => next()
const JWT_SECRET = process.env.JWT_SECRET!

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://example.test')
  res.header('Access-Control-Allow-Credentials', 'true')
  next()
})

app.get('/lookalike', (req, res) => {
  res.json(axios.default.get(req.query.url as string))
})

app.post('/users', (req, res) => {
  const user: User = {
    id: users.length + 1,
    password: String(req.body.password),
    role: 'user'
  }
  users.push(user)
  res.json(user)
})

app.post('/merge', (req, res) => {
  const { target, source } = req.body
  res.json(_.merge(target, source))
})

app.post('/yaml', (req, res) => {
  res.json(yaml.safeLoad(req.body.document))
})

app.get('/users/:id', (req, res) => {
  const id = req.params.id
  res.json(users.find(user => user.id === Number(id) && user.ownerId === req.user.id))
})

app.delete('/admin/users/:id', requireAdmin, (req, res) => {
  users.splice(Number(req.params.id), 1)
  res.sendStatus(204)
})

app.use((_error, _req, res, _next) => {
  res.status(500).json({ error: 'Internal server error' })
})

app.get('/token', (_req, res) => {
  res.json({ token: jwt.sign({ sub: '1' }, JWT_SECRET, { expiresIn: '1h' }) })
})
