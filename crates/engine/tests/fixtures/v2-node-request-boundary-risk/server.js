const session = require("express-session");

app.use(session({
    secret: cookieSecret,
    saveUninitialized: true,
    resave: true
}));
