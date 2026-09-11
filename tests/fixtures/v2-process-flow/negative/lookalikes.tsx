export function run(child_process: any, command: string, args: string[]) {
  return <div>{child_process.spawnSyncSafe(command, args)}</div>
}
