export function run(custom: any, value: string) {
  return <span>{custom.resolve(value)}</span>
}
