app.set('trust proxy', 'loopback')
app.use('/reset', rateLimit({
  keyGenerator (req: any) {
    return req.ip
  }
}))
