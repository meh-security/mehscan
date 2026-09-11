declare const security: any
declare function audit (value: unknown): void

export function inspectUser () {
  return (req: any) => {
    const user = security.authenticatedUsers.get(req.cookies.token)
    const fieldsParam = req.query?.fields as string | undefined
    const requestedFields = fieldsParam ? fieldsParam.split(',').map(field => field.trim()) : []
    let selected: any = {}

    for (const field of requestedFields) {
      selected[field] = user?.data[field]
    }

    audit(selected)
  }
}
