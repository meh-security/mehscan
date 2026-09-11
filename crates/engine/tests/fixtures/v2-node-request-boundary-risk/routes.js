function isLoggedIn(req, res, next) {
    return next();
}

function changeProfile(req, res) {
    return res.send("changed");
}

app.post("/profile", isLoggedIn, changeProfile);
