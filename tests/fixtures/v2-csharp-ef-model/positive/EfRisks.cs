using System.Reflection;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

public class EfRisksController : ControllerBase
{
    private readonly AppDbContext _db;

    public EfRisksController(AppDbContext db) => _db = db;

    [HttpGet("orders/{id}")]
    public async Task<Order> ByFind([FromRoute] int id)
    {
        return await _db.Orders.FindAsync(id);
    }

    [HttpGet("orders/where/{id}")]
    public async Task<Order> ByWhere([FromRoute] int id)
    {
        return await _db.Orders
            .Where(order => order.Id == id)
            .FirstOrDefaultAsync();
    }

    [HttpGet("owners/{ownerId}/orders")]
    public async Task<List<Order>> ByWhereCollection([FromRoute] string ownerId)
    {
        return await _db.Orders
            .Where(order => order.OwnerId == ownerId)
            .ToListAsync();
    }

    [HttpGet("orders/single/{id}")]
    public async Task<Order> ByTerminalPredicate([FromRoute] int id)
    {
        return await _db.Orders.SingleOrDefaultAsync(order => order.Id == id);
    }

    [HttpPut("users")]
    public async Task<IActionResult> Replace([FromBody] User input)
    {
        _db.Users.Update(input);
        await _db.SaveChangesAsync();
        return Ok();
    }

    [HttpPatch("users/{id}")]
    public async Task<IActionResult> Patch([FromRoute] int id, [FromBody] UserPatch patch)
    {
        var user = await _db.Users.FindAsync(id);
        _db.Entry(user).CurrentValues.SetValues(patch);
        await _db.SaveChangesAsync();
        return Ok();
    }

    [HttpGet("users/field")]
    public IActionResult SelectField([FromQuery] string field)
    {
        var user = new User();
        return Ok(typeof(User).GetProperty(field)?.GetValue(user));
    }
}
