export function run(helper: any, destination: string, base: string) {
  return <span>{helper.sameOrigin(destination, base)}</span>
}
