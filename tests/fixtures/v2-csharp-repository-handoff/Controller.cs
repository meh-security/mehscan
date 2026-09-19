using Microsoft.AspNetCore.Mvc;

public class UsersController : ControllerBase
{
    private readonly IUserLookupService _users;

    public UsersController(IUserLookupService users)
    {
        _users = users;
    }

    [HttpGet]
    public object Find([FromQuery] string email) => _users.Lookup(email);
}
