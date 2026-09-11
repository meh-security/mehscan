import * as encoding from '../lib/encoding'
import * as security from 'security-kit'

export function variableAlphabet(req, pool) {
  return pool.query(`SELECT * FROM users WHERE password = '${encoding.hash(req.body.password)}'`)
}

export function unresolvedHelper(req, pool) {
  return pool.query(`SELECT * FROM users WHERE password = '${security.hash(req.body.password)}'`)
}

export function shadowedImport(req, pool, security) {
  return pool.query(`SELECT * FROM users WHERE password = '${security.hash(req.body.password)}'`)
}
