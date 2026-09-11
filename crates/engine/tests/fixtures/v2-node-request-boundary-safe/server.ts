import session from "express-session";
import csrf from "csurf";

app.use(session({
    secret: cookieSecret,
    saveUninitialized: false,
    resave: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "lax"
    }
}));
app.use(csrf());

function isLoggedIn(req, res, next) {
    return next();
}

function changeProfile(req, res) {
    return res.send("changed");
}

app.post("/profile", isLoggedIn, changeProfile);
