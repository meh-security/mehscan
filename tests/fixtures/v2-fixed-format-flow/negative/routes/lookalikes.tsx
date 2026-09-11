import * as encoding from '../lib/encoding'
import * as security from 'security-kit'

export function variableAlphabet(req: any, pool: any) {
  return pool.query(`SELECT * FROM users WHERE password = '${encoding.hash(req.body.password)}'`)
}

export function unresolvedHelper(req: any, pool: any) {
  return pool.query(`SELECT * FROM users WHERE password = '${security.hash(req.body.password)}'`)
}

export function shadowedImport(req: any, pool: any, security: any) {
  return pool.query(`SELECT * FROM users WHERE password = '${security.hash(req.body.password)}'`)
}
