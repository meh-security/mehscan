import vm from 'node:vm'
import yaml from 'js-yaml'
import fakeYaml from 'data-parser'

export function restrictedShape(req: any) {
  const data = req.file.buffer.toString()
  const sandbox = { yaml, data }
  return vm.runInContext('yaml.load(data, { schema: yaml.JSON_SCHEMA })', sandbox)
}

export function wrongLoader(req: any) {
  const data = req.file.buffer.toString()
  const sandbox = { fakeYaml, data }
  return vm.runInContext('fakeYaml.load(data)', sandbox)
}

export function mutatedContext(req: any) {
  const data = req.file.buffer.toString()
  const sandbox = { yaml, data }
  sandbox.data = 'fixed'
  return vm.runInContext('JSON.stringify(yaml.load(data))', sandbox)
}
