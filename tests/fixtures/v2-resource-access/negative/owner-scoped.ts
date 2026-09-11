declare const AddressModel: any

export async function getAddress (req: any) {
  return await AddressModel.findOne({
    where: { id: req.params.id, UserId: req.body.UserId }
  })
}

export async function deleteAddress (req: any) {
  return await AddressModel.destroy({
    where: { id: req.params.id, UserId: req.body.UserId }
  })
}
