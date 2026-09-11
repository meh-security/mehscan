const bcrypt = require("bcrypt");

function SafeDAO(db) {
    const users = db.collection("users");

    this.findOwned = (userId, threshold, callback) => {
        const parsedThreshold = parseInt(threshold, 10);
        users.find({ userId: parseInt(userId, 10), stocks: { $gt: parsedThreshold } }).toArray(callback);
    };

    this.addUser = (username, password, callback) => {
        const passwordHash = bcrypt.hashSync(password, 12);
        users.insert({ username, password: passwordHash }, callback);
    };
}

module.exports = { SafeDAO };
