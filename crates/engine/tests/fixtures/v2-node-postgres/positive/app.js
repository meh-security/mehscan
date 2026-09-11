const { Client } = require('pg');
const client = new Client();

export async function loadUser(req) {
  return client.query(`select * from users where id = ${req.params.id}`);
}
