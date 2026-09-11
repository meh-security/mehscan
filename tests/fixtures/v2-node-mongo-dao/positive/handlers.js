const { AllocationsDAO, BenefitsDAO, UserDAO } = require("./dao");

function Handlers(db) {
    const allocations = new AllocationsDAO(db);
    const benefits = new BenefitsDAO(db);
    const users = new UserDAO(db);

    this.allocations = (req, res) => {
        const { userId } = req.params;
        const { threshold } = req.query;
        return allocations.find(userId, threshold, (_error, rows) => res.json(rows));
    };

    this.updateBenefits = (req, res) => {
        const { userId, startDate } = req.body;
        return benefits.updateBenefits(userId, startDate, () => res.sendStatus(204));
    };

    this.signup = (req, res) => {
        const { username, password } = req.body;
        return users.addUser(username, password, () => res.sendStatus(201));
    };
}

module.exports = Handlers;
