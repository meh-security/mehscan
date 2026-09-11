function ignoredProtection(req, res, he) {
  return res.send(req.query.unencoded + he.encode('constant'))
}
