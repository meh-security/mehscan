using System;

public class CSharpCodeProvider
{
    public void CompileAssemblyFromSource(object options, string source) { }
}

public static class JSON
{
    public static void ToObject(string value, object options) { }
}

public class StandaloneLookalike
{
    public void Run()
    {
        var compiler = new CSharpCodeProvider();
        compiler.CompileAssemblyFromSource(null, Console.ReadLine());
        JSON.ToObject(Console.ReadLine(), new object());
    }
}
