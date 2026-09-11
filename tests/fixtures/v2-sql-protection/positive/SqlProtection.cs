class SqlProtection
{
    void Review(string query, string userId)
    {
        var command = new SqlCommand(query);
        command.Parameters.AddWithValue("@id", userId);
    }
}
