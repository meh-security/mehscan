import * as child_process from 'child_process'

export function executeCommand (command) {
  child_process.exec(command)
}
