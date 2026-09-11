function AllocationsDAO(db) {
    const allocations = db.collection("allocations");
    this.find = (userId, threshold, callback) => {
        const parsedUserId = parseInt(userId, 10);
        allocations.find({
            $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
        }).toArray(callback);
    };
}

function BenefitsDAO(db) {
    const users = db.collection("users");
    this.updateBenefits = (userId, startDate, callback) => {
        users.update({ _id: parseInt(userId, 10) }, { $set: { startDate } }, callback);
    };
}

function UserDAO(db) {
    const users = db.collection("users");
    this.addUser = (username, password, callback) => {
        users.insert({ username, password }, callback);
    };
}

module.exports = { AllocationsDAO, BenefitsDAO, UserDAO };
