import type { Request } from 'express'
import * as models from './models'

export function search (req: Request) {
  let criteria = req.query.q === 'undefined' ? '' : req.query.q ?? ''
  criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200)
  return models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)
}
