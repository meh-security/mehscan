import path from 'node:path'

export function servePublicFiles () {
  return ({ params }: any, res: any) => {
    const file = params.file
    verify(file, res)
  }

  function verify (file: string, res: any) {
    if (file && endsWithAllowlistedFileType(file)) {
      file = security.cutOffPoisonNullByte(file)
      res.sendFile(path.resolve('ftp/', file))
    }
  }
}

declare const security: any
declare function endsWithAllowlistedFileType (file: string): boolean
