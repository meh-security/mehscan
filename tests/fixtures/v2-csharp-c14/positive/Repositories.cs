using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

public interface IQueryRepository { }

public class QueryRepository : IQueryRepository
{
    public object UnsafeSql(string query)
    {
        var command = new SqlCommand();
        command.CommandText = query;
        return command.ExecuteReader();
    }

    public object ParameterizedSql(string value)
    {
        var command = new SqlCommand();
        command.CommandText = "select * from users where name = @name";
        command.Parameters.AddWithValue("@name", value);
        return command.ExecuteReader();
    }
}

public interface IOrderService { }

public class OrderService : IOrderService
{
    private readonly ShopContext _db;
    private readonly ClaimsPrincipal User;

    public object Unscoped(string id) => _db.Orders.Find(id);

    public object Scoped(string id) => _db.Orders
        .Where(order => order.Id == id && order.OwnerId == User.FindFirstValue("sub"))
        .SingleOrDefault();
}

public class ShopContext : DbContext
{
    public DbSet<Order> Orders { get; set; }
}

public class Order
{
    public string Id { get; set; }
    public string OwnerId { get; set; }
}
