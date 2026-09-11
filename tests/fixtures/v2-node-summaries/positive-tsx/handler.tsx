import * as child_process from 'child_process'
import { requestCommand } from './helpers'
import { executeCommand } from './sinks'

export function RunCommand (req: any) {
  const command = requestCommand(req)
  child_process.exec(command)
  return <span>started</span>
}

export function RunThroughSink (req: any) {
  executeCommand(req.params.sinkCommand)
  return <span>started</span>
}
