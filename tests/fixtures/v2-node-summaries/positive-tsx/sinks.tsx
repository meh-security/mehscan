import * as child_process from 'child_process'

export function executeCommand (command: string) {
  child_process.exec(command)
}
