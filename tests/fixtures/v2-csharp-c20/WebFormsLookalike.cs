using System.Web.UI;

public class ClientScriptManager
{
    public void RegisterClientScriptInclude(string name, string value) { }
}

public class Lookalike
{
    public void Run(string value)
    {
        var local = new ClientScriptManager();
        local.RegisterClientScriptInclude("x", value);
    }
}
