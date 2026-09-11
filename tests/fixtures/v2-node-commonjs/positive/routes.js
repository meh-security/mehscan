const ResearchHandler = require("./handler");

const handler = new ResearchHandler();
const isLoggedIn = (_req, _res, next) => next();

module.exports = (app) => {
    app.get("/research", isLoggedIn, handler.displayResearch);
};
