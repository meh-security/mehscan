import vm from 'node:vm'
import yaml from 'js-yaml'
import fakeYaml from 'data-parser'

export function RestrictedShape({ req }: { req: any }) {
  const data = req.file.buffer.toString()
  const sandbox = { yaml, data }
  return vm.runInContext('yaml.load(data, { schema: yaml.JSON_SCHEMA })', sandbox)
}

export function WrongLoader({ req }: { req: any }) {
  const data = req.file.buffer.toString()
  const sandbox = { fakeYaml, data }
  return vm.runInContext('fakeYaml.load(data)', sandbox)
}

export function MutatedContext({ req }: { req: any }) {
  const data = req.file.buffer.toString()
  const sandbox = { yaml, data }
  sandbox.data = 'fixed'
  return vm.runInContext('JSON.stringify(yaml.load(data))', sandbox)
}
