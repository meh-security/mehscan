import type { Request, Response } from 'express'
import * as child_process from 'child_process'
import { conditionalCommand, constantCommand, secondHop } from './helpers'
import { conditionalForward, conditionalSink } from './sinks'

export async function safeHandlers (req: Request, res: Response) {
  child_process.exec(constantCommand(req))
  child_process.exec(conditionalCommand(req, false))
  child_process.exec(secondHop(req))
  res.send('done')
}

export function unsupportedContinuations (req: Request) {
  conditionalSink(req.body.command, false)
  conditionalForward(req.body.command, command => child_process.exec(command), false)
  Promise.resolve('constant').then(command => child_process.exec(command))
  Promise.all([req.body.command]).then(commands => child_process.exec(commands[0]))
}
