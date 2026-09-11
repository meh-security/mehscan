const TOOL = "tool";

export function review(dynamicCommand: string) {
  child_process.exec(`safe/${TOOL}`);
  child_process.exec(`prefix/${dynamicCommand}/suffix`);
}
