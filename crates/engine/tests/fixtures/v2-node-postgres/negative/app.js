const { Client: PgClient } = require('pg');
const database = new PgClient();

export async function loadUser(req) {
  return database.query('select * from users where id = $1', [req.params.id]);
}
