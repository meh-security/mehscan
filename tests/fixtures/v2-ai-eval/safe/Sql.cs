object SafeLookup(dynamic connection, string id)
{
    var command = connection.CreateCommand();
    command.CommandText = "SELECT * FROM users WHERE id = @id";
    command.Parameters.AddWithValue("@id", id);
    return command.ExecuteReader();
}
