import vm from 'node:vm'
import yaml from 'js-yaml'

export function ParseUpload({ req }: { req: any }) {
  const data = req.file.buffer.toString()
  const sandbox = { yaml, data }
  vm.createContext(sandbox)
  return vm.runInContext('JSON.stringify(yaml.load(data))', sandbox)
}
