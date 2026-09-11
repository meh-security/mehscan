import type { Request } from 'express'
import * as models from './models'

export function parameterized (req: Request) {
  const criteria = req.query.q
  return models.sequelize.query('SELECT * FROM Products WHERE name = ?', { replacements: [criteria] })
}

export function transformed (req: Request) {
  let criteria = req.query.q
  criteria = encodeURIComponent(String(criteria))
  return models.sequelize.query(`SELECT * FROM Products WHERE name = '${criteria}'`)
}

export function predicateOnly (req: Request) {
  let criteria = req.query.q === 'undefined' ? 'public' : 'fixed'
  criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200)
  return models.sequelize.query(`SELECT * FROM Products WHERE name = '${criteria}'`)
}
