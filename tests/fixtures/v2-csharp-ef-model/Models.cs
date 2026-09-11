using Microsoft.EntityFrameworkCore;

public class AppDbContext : DbContext
{
    public DbSet<Order> Orders { get; set; }
    public DbSet<User> Users { get; set; }
}

public class Order
{
    public int Id { get; set; }
    public string OwnerId { get; set; }
    public string Description { get; set; }
}

public class User
{
    public int Id { get; set; }
    public string DisplayName { get; set; }
    public string Role { get; set; }
    public bool IsAdmin { get; set; }
    public string PasswordHash { get; set; }
}

public class UserPatch
{
    public string DisplayName { get; set; }
    public string Role { get; set; }
}

public class SafeDbContext : DbContext
{
    public DbSet<SafeOrder> Orders { get; set; }
    public DbSet<SafeUser> Users { get; set; }
}

public class SafeOrder
{
    public int Id { get; set; }
    public string OwnerId { get; set; }
    public string Description { get; set; }
}

public class SafeUser
{
    public int Id { get; set; }
    public string DisplayName { get; set; }
    public string Role { get; set; }
    public bool IsAdmin { get; set; }
    public string PasswordHash { get; set; }
}

public class SafeUserInput
{
    public int Id { get; set; }
    public string DisplayName { get; set; }
}
