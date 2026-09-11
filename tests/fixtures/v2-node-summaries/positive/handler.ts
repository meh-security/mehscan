import type { Request, Response } from 'express'
import * as child_process from 'child_process'
import { requestCommand } from './helpers'
import {
  continueWith,
  deserialize,
  executeCommand,
  readPath,
  redirectTo,
  requestUrl,
  runCode,
  sendHtml
} from './sinks'

export async function runCommand (req: Request, res: Response) {
  const command = requestCommand(req)
  child_process.exec(command)
  res.send('started')
}

export function runThroughSink (req: Request) {
  executeCommand(req.body.sinkCommand)
  runCode(req.body.code)
  readPath(req.body.path)
  requestUrl(req.body.url)
  redirectTo({ redirect: (_location: string) => undefined }, req.body.redirect)
  deserialize(req.body.payload)
  sendHtml({ send: (_content: string) => undefined }, req.body.html)
}

export function runPromise (req: Request) {
  return Promise.resolve(req.body.promiseCommand).then(command => {
    child_process.exec(command)
  })
}

export function runCallback (req: Request) {
  continueWith(req.body.callbackCommand, command => {
    child_process.exec(command)
  })
}
