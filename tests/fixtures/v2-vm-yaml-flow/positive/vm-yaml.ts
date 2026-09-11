import vm from 'node:vm'
import yaml from 'js-yaml'
import type { Request } from 'express'

export function parseUpload() {
  return ({ file }: Request) => {
    if (file?.buffer) {
      const data = file.buffer.toString()
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        return vm.runInContext('JSON.stringify(yaml.load(data))', sandbox)
      } catch (error) {
        throw error
      }
    }
  }
}
