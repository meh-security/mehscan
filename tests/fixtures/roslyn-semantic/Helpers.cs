public static class Helpers
{
    public static string Build(string input)
    {
        return "SELECT name FROM users WHERE name='" + input + "'";
    }
}
