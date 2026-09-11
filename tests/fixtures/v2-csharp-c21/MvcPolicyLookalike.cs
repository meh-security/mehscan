public class ValidateInputAttribute : System.Attribute
{
    public ValidateInputAttribute(bool enabled) { }
}

public class LocalController
{
    [ValidateInput(false)]
    public void Accept(string content) { }
}
