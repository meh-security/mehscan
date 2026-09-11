const ejs = require('ejs');

function renderNotFound(input) {
  return ejs.render('<h1>Missing <%= path %></h1>', { path: input });
}

function showMissing(req, res) {
  return res.send(renderNotFound(req.query.path));
}

function findNotes(req, res, db) {
  if (typeof req.body.username !== 'string') {
    return res.status(400).send('username must be a string');
  }
  return db.collection('notes').find({ username: req.body.username }).toArray();
}

module.exports = { showMissing, findNotes };
