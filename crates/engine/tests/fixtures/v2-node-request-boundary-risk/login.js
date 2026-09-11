function validateSignup(password) {
    const PASS_RE = /^.{1,20}$/;
    return PASS_RE.test(password);
}

function login(req, res, next) {
    userDAO.validateLogin(req.body.userName, req.body.password, (error, user) => {
        if (error) return next(error);
        req.session.userId = user.id;
        return res.redirect("/dashboard");
    });
}
