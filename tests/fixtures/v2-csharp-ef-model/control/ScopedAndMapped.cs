using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

public class ScopedAndMappedController : ControllerBase
{
    private readonly SafeDbContext _db;

    public ScopedAndMappedController(SafeDbContext db) => _db = db;

    [HttpGet("orders/{id}")]
    public async Task<SafeOrder> Owned([FromRoute] int id)
    {
        return await _db.Orders
            .Where(order => order.Id == id &&
                            order.OwnerId == User.FindFirstValue(ClaimTypes.NameIdentifier))
            .SingleOrDefaultAsync();
    }

    [HttpPut("users")]
    public async Task<IActionResult> MapFields([FromBody] SafeUserInput input)
    {
        _db.Users.Update(new SafeUser
        {
            Id = input.Id,
            DisplayName = input.DisplayName
        });
        await _db.SaveChangesAsync();
        return Ok();
    }

    [HttpGet("users/field")]
    public IActionResult AllowedField([FromQuery] string field)
    {
        var allowed = new HashSet<string> { "Id", "DisplayName" };
        if (!allowed.Contains(field))
            return BadRequest();

        var user = new SafeUser();
        return Ok(typeof(SafeUser).GetProperty(field)?.GetValue(user));
    }
}
