export const jsonEnvelope = <T>(value: T): { data: T } => {
  return { data: value }
}

export const dynamicEnvelope = (value: unknown): unknown => {
  return value
}
