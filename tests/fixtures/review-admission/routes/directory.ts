import fs from 'node:fs'

export function checksumDirectory () {
  fs.readdirSync('dist/').forEach(file => {
    fs.readFileSync('dist/' + file)
  })
}

export function dynamicDirectory (base: string, file: string) {
  fs.readFileSync(base + file)
}
