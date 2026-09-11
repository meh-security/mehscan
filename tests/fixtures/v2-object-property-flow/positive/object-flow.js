import vm from 'node:vm'
import { eval as safeEval } from 'notevil'

export function evaluateOrder(req) {
  const orderData = req.body.orderData
  const sandbox = { safeEval, orderData }
  vm.createContext(sandbox)
  return vm.runInContext('safeEval(orderData)', sandbox)
}
