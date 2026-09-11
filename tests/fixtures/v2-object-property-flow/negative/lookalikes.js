import vm from 'node:vm'
import { parse as safeEval } from 'data-parser'
import { eval as dangerousEval } from 'notevil'

export function constantProgram(req, parser) {
  const data = req.body.data
  const sandbox = { parser, data }
  return vm.runInContext('parser.parse(data)', sandbox)
}

export function nonEvaluator(req) {
  const data = req.body.data
  const sandbox = { safeEval, data }
  return vm.runInContext('safeEval(data)', sandbox)
}

export function mutatedContext(req) {
  const data = req.body.data
  const sandbox = { safeEval: dangerousEval, data }
  sandbox.data = 'fixed'
  return vm.runInContext('safeEval(data)', sandbox)
}
