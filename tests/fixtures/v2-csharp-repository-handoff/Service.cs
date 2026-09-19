public interface IUserLookupService { }

public class UserLookupService : IUserLookupService
{
    private readonly IUserRepository _users;

    public UserLookupService(IUserRepository users)
    {
        _users = users;
    }

    public object Lookup(string email) => _users.FindByEmail(email);
}
