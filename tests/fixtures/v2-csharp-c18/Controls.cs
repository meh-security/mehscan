using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

public class SecureUsersController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;

    [HttpPost]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AddByRole(AdminInput model)
    {
        var user = new IdentityUser(model.Username);
        if (model.MakeAdmin)
        {
            await _userManager.AddToRoleAsync(user, "admin");
        }
        return Ok();
    }

    [HttpPost]
    public async Task<IActionResult> AddByPrincipal(AdminInput model)
    {
        if (!User.IsInRole("Admin"))
        {
            return Forbid();
        }
        var user = new IdentityUser(model.Username);
        if (model.MakeAdmin)
        {
            await _userManager.AddToRoleAsync(user, "admin");
        }
        return Ok();
    }
}
