declare const DeliveryModel: any

export async function listDeliveryMethods () {
  return await DeliveryModel.findAll()
}

export async function getDeliveryMethod (req: any) {
  return await DeliveryModel.findOne({ where: { id: req.params.id } })
}
