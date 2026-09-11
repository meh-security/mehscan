const execFile = require('child_process').execFile;
const libxml = require('libxmljs');
const mysql = require('mysql2');

const connection = mysql.createConnection({});

function safer(req) {
  execFile('/usr/bin/ping', ['-c', '1', req.body.host]);
  connection.query('select * from users where name = ?', [req.body.name]);
  libxml.parseXmlString(req.body.xml, { noent: false, nonet: true });
  JSON.parse(req.body.preference);
}

module.exports = safer;
