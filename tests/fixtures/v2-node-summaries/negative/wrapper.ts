export const loggingOnly = (_handler: any) => async (_req: any, _res: any, next: any) => {
  next()
}
