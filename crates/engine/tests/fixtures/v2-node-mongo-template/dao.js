function ContentDAO(db) {
    const content = db.collection("content");

    this.getById = (id, callback) => {
        content.findOne({ _id: id }, callback);
    };
}

exports.ContentDAO = ContentDAO;
