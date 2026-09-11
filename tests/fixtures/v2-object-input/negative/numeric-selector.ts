import type { Request } from 'express'

export function findReview (req: Request, reviewsCollection: any) {
  const id = Number(req.params.id)
  return reviewsCollection.find({ _id: id })
}
