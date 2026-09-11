Object safeLookup(Connection connection, String id) throws Exception {
    PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
    statement.setString(1, id);
    return statement.executeQuery();
}
