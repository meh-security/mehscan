export function findPublished (reviewsCollection: any) {
  return reviewsCollection.find({ published: true })
}
