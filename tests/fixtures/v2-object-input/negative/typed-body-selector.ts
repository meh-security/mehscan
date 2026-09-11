import type { Request } from 'express'

export function updateReview (req: Request, reviewsCollection: any) {
  if (typeof req.body.id !== 'string') {
    return
  }
  return reviewsCollection.update({ _id: req.body.id }, { $set: { message: 'safe' } })
}
