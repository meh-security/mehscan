const needle = {
    get(value) {
        return value;
    }
};

module.exports = function localLookup() {
    return needle.get("fixed-local-name");
};
