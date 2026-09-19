using Microsoft.Data.SqlClient;

public interface IUserRepository { }

public class UserRepository : IUserRepository
{
    public object FindByEmail(string email)
    {
        var command = new SqlCommand();
        command.CommandText = "select * from users where email = '" + email + "'";
        return command.ExecuteReader();
    }
}
