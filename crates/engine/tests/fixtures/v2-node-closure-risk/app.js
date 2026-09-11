const http = require("http");

function login(req, res) {
    const { userName } = req.body;
    authenticate(userName, err => {
        const unknown = "Invalid username";
        const badPassword = "Invalid password";
        if (err.noSuchUser) {
            console.log("Invalid login", userName);
            return res.render("login", { loginError: unknown });
        }
        if (err.invalidPassword) {
            return res.render("login", { loginError: badPassword });
        }
    });
}

function saveProfile(users, ssn, dateOfBirth) {
    const profile = {};
    profile.ssn = ssn;
    profile.dateOfBirth = dateOfBirth;
    users.updateOne({}, { $set: profile });
}

http.createServer(app).listen(3000);

// Comments are not executable controls.
// console.log(req.body.userName.replace(/(\r\n|\r|\n)/g, "_"));
// https.createServer(options, app).listen(3000);
