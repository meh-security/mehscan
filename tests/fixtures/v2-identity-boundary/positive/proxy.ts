app.enable('trust proxy')
app.use('/reset', rateLimit({
  keyGenerator ({ headers, ip }: any) {
    return headers['X-Forwarded-For'] ?? ip
  }
}))
