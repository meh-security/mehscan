class SqlProtection {
    void review(Connection connection, String query, String userId) throws Exception {
        var statement = connection.prepareStatement(query);
        statement.setString(1, userId);
    }
}
