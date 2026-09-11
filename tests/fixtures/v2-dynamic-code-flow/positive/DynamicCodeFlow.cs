class DynamicCodeFlow
{
    object Direct(dynamic Request)
    {
        return CSharpScript.EvaluateAsync(Request.Form["code"]);
    }

    object Propagated(dynamic Request)
    {
        var code = Request.Form["code"];
        var forwardedValue = code;
        return CSharpScript.EvaluateAsync(forwardedValue);
    }

    object Restricted(dynamic Request)
    {
        return CSharpScript.EvaluateAsync(
            Request.Form["restricted"],
            ScriptOptions.Default.WithReferences(typeof(SafeGlobals).Assembly));
    }
}
