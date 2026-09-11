using System.Net.Http;

class Surfaces
{
    void Review(string query, string url, string path, string code, HttpClient client)
    {
        var command = new SqlCommand(query);
        client.GetAsync(url);
        File.ReadAllText(path);
        File.WriteAllText(path, "content");
        CSharpScript.EvaluateAsync(code);
    }
}
