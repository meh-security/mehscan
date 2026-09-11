const ejs = require('ejs');

function renderNotFound(input) {
  const template = '<h1>Missing ' + input + '</h1>';
  return ejs.render(template, { product: 'scanner' });
}

function showMissing(req, res) {
  const requestedPath = req.query.path;
  return res.send(renderNotFound(requestedPath));
}

function findNotes(req, res, db) {
  return db.collection('notes').find({ username: req.body.username }).toArray();
}

module.exports = { showMissing, findNotes };
