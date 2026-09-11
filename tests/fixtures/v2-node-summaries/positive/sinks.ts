import * as child_process from 'child_process'
import * as fs from 'fs'
import * as yaml from 'js-yaml'

export function executeCommand (command: string) {
  child_process.exec(command)
}

export function continueWith (value: string, callback: (value: string) => void) {
  callback(value)
}

export function runCode (code: string) {
  eval(code)
}

export function readPath (path: string) {
  fs.readFileSync(path)
}

export function requestUrl (endpoint: string) {
  fetch(endpoint)
}

export function redirectTo (res: any, location: string) {
  res.redirect(location)
}

export function deserialize (payload: string) {
  yaml.load(payload)
}

export function sendHtml (res: any, content: string) {
  res.send(content)
}
