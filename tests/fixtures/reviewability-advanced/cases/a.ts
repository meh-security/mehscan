export function lookup(req: any, models: any) {
  return models.sequelize.query('SELECT id FROM users WHERE email = :email', { replacements: { email: req.body.email } })
}
