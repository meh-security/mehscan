import vm from 'node:vm'
import { eval as safeEval } from 'notevil'
import type { Request } from 'express'

export function evaluateOrder() {
  return ({ body }: Request) => {
    if (body.enabled) {
      const orderData = body.orderData || ''
      try {
        const sandbox = { safeEval, orderData }
        vm.createContext(sandbox)
        return vm.runInContext('safeEval(orderData)', sandbox, { timeout: 2000 })
      } catch (error) {
        throw error
      }
    }
  }
}
