const { SafeDAO } = require("./dao");

function SafeHandlers(db) {
    const dao = new SafeDAO(db);

    this.allocations = (req, res) => {
        const { userId } = req.session;
        const threshold = Number(req.query.threshold);
        return dao.findOwned(userId, threshold, (_error, rows) => res.json(rows));
    };

    this.signup = (req, res) => {
        const { username, password } = req.body;
        return dao.addUser(username, password, () => res.sendStatus(201));
    };
}

module.exports = SafeHandlers;
