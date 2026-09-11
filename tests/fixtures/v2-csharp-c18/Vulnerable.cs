using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[Authorize]
public class UsersController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;

    [HttpPost]
    public async Task<IActionResult> AddUser(AdminInput model)
    {
        if (!model.IsIssuerAdmin)
        {
            return RedirectToAction("Login");
        }

        var user = new IdentityUser(model.Username);
        if (model.MakeAdmin)
        {
            await _userManager.AddToRoleAsync(user, "admin");
        }
        return Ok();
    }
}

public class AdminInput
{
    public string Username { get; set; }
    public bool IsIssuerAdmin { get; set; }
    public bool MakeAdmin { get; set; }
}
