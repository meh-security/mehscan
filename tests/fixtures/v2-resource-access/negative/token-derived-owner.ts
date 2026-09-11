declare const InvoiceModel: any

export async function getInvoice (req: any) {
  const ownerId = req.user.id
  return await InvoiceModel.findOne({
    where: { id: req.params.id, owner_id: ownerId }
  })
}
