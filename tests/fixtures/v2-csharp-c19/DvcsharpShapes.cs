using System.Linq;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

public class Account
{
    public int Id { get; set; }
    public string Role { get; set; }
}

public class AccountUpdate
{
    public string Role { get; set; }
}

public class AppDataContext : DbContext
{
    public DbSet<Account> Accounts { get; set; }
}

[Authorize]
public class AccountsController : Controller
{
    private readonly AppDataContext _context;

    [HttpGet("search")]
    public IActionResult Search(string keyword)
    {
        var query = $"SELECT * FROM Accounts WHERE Name LIKE '%{keyword}%'";
        return Ok(_context.Accounts.FromSql(query).ToList());
    }

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch()
    {
        var client = new HttpClient();
        var url = HttpContext.Request.Query["url"].ToString();
        return Ok(await client.GetStringAsync(url));
    }

    [HttpPut("{id}")]
    public IActionResult Update(int id, [FromBody] AccountUpdate input)
    {
        var account = _context.Accounts.Single(item => item.Id == id);
        account.Role = input.Role;
        _context.Accounts.Update(account);
        _context.SaveChanges();
        return Ok(account);
    }

    [Authorize(Roles = "Administrator")]
    [HttpPut("admin/{id}")]
    public IActionResult AdminUpdate(int id, [FromBody] AccountUpdate input)
    {
        var account = _context.Accounts.Single(item => item.Id == id);
        account.Role = input.Role;
        _context.Accounts.Update(account);
        _context.SaveChanges();
        return Ok(account);
    }

    [HttpGet("safe-search")]
    public IActionResult SafeSearch(string keyword)
    {
        return Ok(_context.Accounts.FromSql($"SELECT * FROM Accounts WHERE Name = {keyword}").ToList());
    }
}

public class FakeSet
{
    public object FromSql(string query) => query;
}

public class Lookalikes
{
    public object Search(string input)
    {
        var fake = new FakeSet();
        return fake.FromSql(input);
    }
}
