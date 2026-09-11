import * as security from '../lib/insecurity'

export function login(req, pool) {
  return pool.query(`SELECT * FROM users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`)
}
