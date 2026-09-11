export function RunButton(props: { command: string }) {
  child_process.execSync(props.command);
  return <button>Run</button>;
}

