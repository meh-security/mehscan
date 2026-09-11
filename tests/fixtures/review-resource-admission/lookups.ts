declare const RecordModel: any

export function fixedObjectLookup () {
  return RecordModel.findOne({ where: { id: 1, tenant: 'system' } })
}

export function dynamicObjectLookup (req: any) {
  return RecordModel.findOne({ where: { id: 1, tenant: req.user.tenant } })
}
