import type { Request } from 'express'

export function updateReviews (req: Request, reviewsCollection: any) {
  return reviewsCollection.update(
    { _id: req.body.id },
    { $set: { message: req.body.message } },
    { multi: true }
  )
}
