import { exec as run } from "node:child_process";
import * as cp from "node:child_process";

export function review(command) {
  run(command);
  cp.spawn(command);
}

export function shadowed(cp, command) {
  cp.spawn(command);
}
