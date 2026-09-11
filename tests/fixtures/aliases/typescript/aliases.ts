const cp = require("child_process");
const { exec: run } = require("child_process");

export function review(command: string) {
  cp.exec(command);
  run(command);
}

export function shadowed(cp: { exec(command: string): void }, command: string) {
  cp.exec(command);
}
