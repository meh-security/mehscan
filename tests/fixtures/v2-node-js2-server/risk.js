const exec = require('child_process').exec;
const libxml = require('libxmljs');
const serialize = require('node-serialize');
const mysql = require('mysql2');
const pdf = require('html-pdf-node');
const MongoClient = require('mongodb').MongoClient;
const { graphqlHTTP } = require('express-graphql');

const connection = mysql.createConnection({});
const graphqlroot = { user: lookupUser };

function lookupUser(args) {
  const query = "select * from users where name='" + args.name + "'";
  return connection.promise().query(query);
}

function vulnerable(req) {
  exec('ping ' + req.body.host);
  serialize.unserialize(req.cookies.preference);
  libxml.parseXmlString(req.body.xml, { noent: true, nonet: false });
  pdf.generatePdf({ url: req.query.url }, {});
  MongoClient.connect('mongodb://localhost', (_error, client) => {
    client.db('test').collection('users').find({
      $where: "this.password == '" + req.body.password + "'",
    });
  });
}

function closureQuery(req) {
  const name = req.query.name;
  const query = "select * from users where name='" + name + "'";
  connection.connect(() => connection.query(query, () => {}));
}

graphqlHTTP({ rootValue: graphqlroot });
module.exports = vulnerable;
