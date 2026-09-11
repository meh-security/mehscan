const session = require("express-session");

app.use(session({
    secret: cookieSecret,
    cookie: {
        httpOnly: false,
        secure: false,
        sameSite: "none"
    }
}));
