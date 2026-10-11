export function useState(value: string): [string, (s: string) => void] { return [value, () => {}]; }
