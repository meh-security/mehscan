const express = require('express')
const app = express()

app.set('view engine', 'pug')
app.get('/hello', (req, res) => {
  res.render('hello', { name: req.query.name })
})

app.get('/plain', (req, res) => {
  res.set('Content-Type', 'text/plain').send(req.query.message)
})
