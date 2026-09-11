function login(req, res, next) {
    const PASSWORD_PATTERN = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{12,}$/;
    if (!PASSWORD_PATTERN.test(req.body.password)) {
        return res.send("invalid");
    }
    userService.authenticate(req.body.userName, req.body.password, (error, user) => {
        if (error) return next(error);
        req.session.regenerate(() => {
            req.session.userId = user.id;
            return res.redirect("/dashboard");
        });
    });
}
