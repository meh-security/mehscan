class Ordinary {
    object Run(string script) => Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync<object>(script);
}
