import type { Request } from 'express'
import { ProductModel } from '../model'

export function createProduct (req: Request) {
  return ProductModel.create(req.body)
}
