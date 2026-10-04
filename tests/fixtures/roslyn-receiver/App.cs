using System;
using Microsoft.Data.SqlClient;

public class Commands
{
    public void Constructed(string input, string connectionString)
    {
        using var connection = new SqlConnection(connectionString);
        using var command = new SqlCommand("SELECT * FROM Items WHERE Name='" + input + "'", connection);
        connection.Open();
        command.ExecuteReader();
    }

    public void Assigned(string input, string connectionString)
    {
        using var connection = new SqlConnection(connectionString);
        using var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        command.Connection = connection;
        connection.Open();
        command.ExecuteReader();
    }

    public void Empty(string input)
    {
        using var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        command.ExecuteReader();
    }

    public void Passed(string input, Action<SqlCommand> configure)
    {
        using var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        configure(command);
        command.ExecuteReader();
    }

    public void Replaced(string input, SqlCommand other)
    {
        var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        command = other;
        command.ExecuteReader();
    }

    public Action Captured(string input)
    {
        var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        return () => command.ExecuteReader();
    }

    public void Conditional(string input, SqlConnection connection, bool attach)
    {
        var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        if (attach) command.Connection = connection;
        command.ExecuteReader();
    }

    public void Many(string input)
    {
        var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
        command.CommandTimeout = 1;
        command.CommandTimeout = 2;
        command.CommandTimeout = 3;
        command.CommandTimeout = 4;
        command.CommandTimeout = 5;
        command.CommandTimeout = 6;
        command.CommandTimeout = 7;
        command.CommandTimeout = 8;
        command.CommandTimeout = 9;
        command.ExecuteReader();
    }

    public void Shadow(string input)
    {
        {
            var command = new SqlCommand { CommandText = "SELECT * FROM Items WHERE Name='" + input + "'" };
            command.ExecuteReader();
        }
        {
            var command = new SqlCommand();
            command.CommandTimeout = 42;
        }
    }
}
