import * as express from 'express'
import * as axios from 'axios'
import * as fs from 'fs'
import * as path from 'path'
import * as yaml from 'js-yaml'
import * as _ from 'lodash'
import * as jwt from 'jsonwebtoken'

interface User {
  id: number
  password: string
  role: string
  ownerId: number
}

const users: User[] = []
const app = express()
const JWT_SECRET: string = 'hardcoded-test-signing-secret'

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Credentials', 'true')
  next()
})

app.get('/proxy', async (req, res) => {
  const url = req.query.url as string
  res.json((await axios.default.get(url)).data)
})

app.get('/files', (req, res) => {
  const filename = req.query.filename as string
  const filePath = path.join(__dirname, 'uploads', filename)
  fs.readFile(filePath, () => res.sendStatus(204))
})

app.post('/users', (req, res) => {
  const user: User = { id: users.length + 1, ...req.body }
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
  res.json(users.find(user => user.id === Number(id)))
})

app.delete('/admin/users/:id', (req, res) => {
  users.splice(Number(req.params.id), 1)
  res.sendStatus(204)
})

app.get('/debug', (_req, res) => {
  res.json({ environment: process.env })
})

app.use((error, _req, res, _next) => {
  res.status(500).json({ stack: error.stack })
})

app.get('/token', (_req, res) => {
  res.json({ token: jwt.sign({ sub: '1' }, JWT_SECRET, { expiresIn: '1h' }) })
})
