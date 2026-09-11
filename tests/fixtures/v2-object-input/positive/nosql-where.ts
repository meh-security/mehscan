import type { Request } from 'express'

export function findOrders (req: Request, ordersCollection: any) {
  const id = req.params.id
  return ordersCollection.find({ $where: `this.orderId === '${id}'` })
}
