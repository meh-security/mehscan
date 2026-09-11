const ContentDAO = require("./dao").ContentDAO;

function Routes(db) {
    const content = new ContentDAO(db);

    this.profile = (req, res, next) => {
        content.getById(req.params.id, (error, doc) => {
            if (error) return next(error);
            return res.render("profile", { ...doc });
        });
    };

    this.memo = (req, res, next) => {
        content.getById(req.params.id, (error, doc) => {
            if (error) return next(error);
            return res.render("memos", { memo: doc });
        });
    };

    this.unused = (req, res, next) => {
        content.getById(req.params.id, (error, doc) => {
            if (error) return next(error);
            return res.render("dashboard", { ...doc });
        });
    };

    this.audit = (req, res, next) => {
        content.getById(req.params.id, (error, doc) => {
            if (error) return next(error);
            console.log(doc);
            return res.send("done");
        });
    };
}

module.exports = Routes;
