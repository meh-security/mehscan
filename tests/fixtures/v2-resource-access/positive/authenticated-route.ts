declare const InvoiceModel: any

export async function getInvoice (req: any) {
  return await InvoiceModel.findOne({ where: { id: req.params.id } })
}
