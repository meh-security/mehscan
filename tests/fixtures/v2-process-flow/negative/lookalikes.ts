function run(child_process: any, command: string, args: string[]) {
  child_process.spawnSafely(command, args)
}
