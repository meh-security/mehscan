export default async function handler(req, res) {
  if (req.method === 'GET') {
    const id = req.query.id
    const item = await repository.findById(id)
    return res.status(200).json(item)
  }
  return res.status(405).end()
}
