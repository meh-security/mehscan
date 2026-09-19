using System.Data;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

public class User { }

public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
}

public class DynamicSqlStore
{
    public object CommandConstructor(string email, IDbConnection connection)
    {
        return new SqlCommand("select * from users where email = '" + email + "'", connection);
    }

    public object CommandText(string email)
    {
        var command = new SqlCommand();
        command.CommandText = $"select * from users where email = '{email}'";
        return command;
    }

    public object DapperQuery(string email, IDbConnection connection)
    {
        var sql = "select * from users where email = '" + email + "'";
        return connection.Query<User>(sql);
    }

    public object EfCoreQuery(string email, AppDbContext context)
    {
        return context.Users.FromSqlRaw("select * from users where email = '" + email + "'");
    }

    public object EfCoreExecute(string email, AppDbContext context)
    {
        return context.Database.ExecuteSqlRaw(
            string.Format("delete from users where email = '{0}'", email));
    }

    public object EfDatabaseQuery(string email, AppDbContext context)
    {
        return context.Database.SqlQuery<User>("select * from users where email = '" + email + "'");
    }

    public object EfExecute(string email, AppDbContext context)
    {
        return context.Database.ExecuteSqlCommand("delete from users where email = '" + email + "'");
    }

    public object Parameterized(string email, IDbConnection connection, AppDbContext context)
    {
        connection.Query<User>("select * from users where email = @email", new { email });
        return context.Database.ExecuteSqlRaw("delete from users where email = {0}", email);
    }

    public object ConstrainedNumeric(int id, IDbConnection connection)
    {
        return new SqlCommand("select * from users where id = " + id, connection);
    }
}
