using System.Data.Common;
using Microsoft.Data.SqlClient;

public static class Queries
{
    public static void Mixed(DbConnection db, int id, string input)
    {
        var query = $"SELECT * FROM Items WHERE Id={id} AND Name='{input}'";
        using var command = db.CreateCommand();
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void Reset(DbCommand command, string input)
    {
        var query = "SELECT * FROM Items WHERE Name='" + input + "'";
        query = "SELECT 1";
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void Conditional(DbCommand command, string input, bool flag)
    {
        var query = "SELECT * FROM Items WHERE Name='" + input + "'";
        if (flag) query = "SELECT 1";
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void Append(DbCommand command, string input)
    {
        var query = "SELECT * FROM Items WHERE Name='";
        query += input;
        query += "'";
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void BothBranches(DbCommand command, string input, bool flag)
    {
        var query = input;
        if (flag) query = "SELECT 1";
        else query = "SELECT 2";
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void Loop(DbCommand command, string input, int count)
    {
        var query = "SELECT 1";
        for (int i = 0; i < count; i++) query += input;
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void Helper(DbCommand command, string input)
    {
        command.CommandText = Build(input);
        command.ExecuteScalar();
    }
    static string Build(string value) => "SELECT * FROM Items WHERE Name='" + value + "'";
    public static void Bound(SqlConnection connection, string input)
    {
        using var command = new SqlCommand("SELECT * FROM Items WHERE Name=@name", connection);
        command.Parameters.AddWithValue("@name", input);
        command.ExecuteScalar();
    }
    public static void Unconnected(string input)
    {
        using var command = new SqlCommand("SELECT * FROM Items WHERE Name='" + input + "'");
        command.ExecuteScalar();
    }
    public static void Tuple(DbCommand command, string input)
    {
        var query = "SELECT 1";
        (query, input) = (input, query);
        command.CommandText = query;
        command.ExecuteScalar();
    }
    public static void LateCapture(DbCommand command, string input)
    {
        var query = input;
        Change();
        command.CommandText = query;
        command.ExecuteScalar();
        void Change() { query = "SELECT 1"; }
    }
}
