import * as child_process from 'child_process'
import { requestCommand } from './helpers'
import { executeCommand as execute } from './sinks'

export function runCommand (req, res) {
  const command = requestCommand(req)
  child_process.exec(command)
  res.send('started')
}

export function runThroughSink (req) {
  execute(req.query.sinkCommand)
}
