declare const security: any

export function retrieveAllowlistedUser () {
  return (req: any, res: any) => {
    const user = security.authenticatedUsers.get(req.cookies.token)
    const fieldsParam = req.query?.fields as string | undefined
    const allowedFields = ['id', 'email']
    const requestedFields = fieldsParam
      ? fieldsParam.split(',').map(field => field.trim()).filter(field => allowedFields.includes(field))
      : []
    let baseUser: any = {}

    for (const field of requestedFields) {
      baseUser[field] = user?.data[field]
    }

    let response: any
    response = { user: baseUser }
    res.json(response)
  }
}
