const needle = require("needle");

function ResearchHandler() {
    this.displayResearch = (req, res) => {
        const endpoint = req.query.url;
        return needle.get(endpoint, (_error, _response, body) => res.send(body));
    };
}

module.exports = ResearchHandler;
