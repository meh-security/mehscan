import vm from 'node:vm'
import { eval as safeEval } from 'notevil'

export function EvaluateOrder({ req }: { req: any }) {
  const orderData = req.body.orderData
  const sandbox = { safeEval, orderData }
  vm.createContext(sandbox)
  return vm.runInContext('safeEval(orderData)', sandbox)
}
