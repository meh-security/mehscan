declare const DocumentModel: any

export async function getDocument (req: any) {
  return await DocumentModel.findOne({ where: { id: req.params.id } })
}
