export function retrievePreferences () {
  return (req: any, res: any) => {
    const fieldsParam = req.query?.fields as string | undefined
    const requestedFields = fieldsParam ? fieldsParam.split(',').map(field => field.trim()) : []
    const preferences: Record<string, string> = { theme: 'dark' }
    let selected: any = {}

    for (const field of requestedFields) {
      selected[field] = preferences[field]
    }

    let response: any
    response = { preferences: selected }
    res.json(response)
  }
}
