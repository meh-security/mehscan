import vm from 'node:vm'

const xmlRegisterFsInputProviders = () => undefined
xmlRegisterFsInputProviders()

export async function parseXmlString (data: string): Promise<string> {
  const libxml2: any = await Promise.resolve({})
  const option = libxml2.ParseOption.XML_PARSE_NOENT | libxml2.ParseOption.XML_PARSE_DTDLOAD
  const sandbox = { libxml2, data, option }
  return vm.runInContext('libxml2.XmlDocument.fromString(data, { option })', sandbox)
}
