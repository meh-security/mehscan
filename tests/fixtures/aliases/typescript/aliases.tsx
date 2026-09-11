import { execSync as runSync } from "node:child_process";

export function Review(props: { command: string }) {
  runSync(props.command);
  return <button>Run</button>;
}

export function Shadowed(runSync: (command: string) => void, command: string) {
  runSync(command);
  return <button>Run</button>;
}
