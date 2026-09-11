const TOOL = "tool";

export function Review() {
  child_process.exec(`safe/${TOOL}`);
  return <div />;
}
