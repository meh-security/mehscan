using Microsoft.AspNetCore.Mvc;

public class UserManager<T>
{
    public Task AddToRoleAsync(T user, string role) => Task.CompletedTask;
}

public class LookalikeController : Controller
{
    private readonly UserManager<object> _userManager;

    [HttpPost]
    public async Task<IActionResult> Assign(Input model)
    {
        if (model.MakeAdmin)
        {
            await _userManager.AddToRoleAsync(new object(), "admin");
        }
        return Ok();
    }
}

public class Input
{
    public bool MakeAdmin { get; set; }
}
