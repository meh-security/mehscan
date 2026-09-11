import * as child_process from 'child_process'

export function conditionalSink (command: string, enabled: boolean) {
  if (enabled) child_process.exec(command)
}

export function conditionalForward (
  value: string,
  callback: (value: string) => void,
  enabled: boolean
) {
  if (enabled) callback(value)
}
