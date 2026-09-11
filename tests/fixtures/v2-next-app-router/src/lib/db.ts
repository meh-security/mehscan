import postgres from "postgres"

const sql = postgres(process.env.DATABASE_URL!)

export async function query(table: string, filter: string) {
  return sql.unsafe(`SELECT * FROM ${table} WHERE ${filter}`)
}

export async function getById(table: string, id: string) {
  return sql.unsafe(`SELECT * FROM ${table} WHERE id = '${id}'`)
}

export async function updateRow(table: string, id: string, data: object) {
  return sql.unsafe(`UPDATE ${table} SET value = '${JSON.stringify(data)}' WHERE id = '${id}'`)
}

export async function insertRow(table: string, data: object) {
  return sql.unsafe(`INSERT INTO ${table} VALUES ('${JSON.stringify(data)}')`)
}
