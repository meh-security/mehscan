import https from "https";

function login(req, res) {
    const generic = "Invalid username or password";
    if (req.error.noSuchUser) {
        console.log("Invalid login", req.body.userName.replace(/(\r\n|\r|\n)/g, "_"));
        return res.render("login", { loginError: generic });
    }
    if (req.error.invalidPassword) {
        return res.render("login", { loginError: generic });
    }
}

function saveProfile(users, ssn, dateOfBirth) {
    const profile = {};
    profile.ssn = encrypt(ssn);
    profile.dateOfBirth = encrypt(dateOfBirth);
    users.updateOne({}, { $set: profile });
}

https.createServer(options, app).listen(3000);

// http.createServer(app).listen(3000);
