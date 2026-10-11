using System.Data.Common;

public class Review
{
    // Unicode offset check: café 🔒 中文
    public void Raw(DbCommand command, string input)
    {
        var query = Helpers.Build(input);
        command.CommandText = query;
        command.ExecuteNonQuery();
    }

    public void Bound(DbCommand command, string input)
    {
        command.CommandText = "SELECT @value";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "@value";
        parameter.Value = input;
        command.Parameters.Add(parameter);
        command.ExecuteNonQuery();
    }

    public void Changed(DbCommand command, string input)
    {
        var query = "SELECT 1";
        query = input;
        command.CommandText = query;
        command.ExecuteNonQuery();
    }

    public void Missing(DbCommand command, string input)
    {
        var query = MissingPolicy.Build(input);
        command.CommandText = query;
        command.ExecuteNonQuery();
    }
}
