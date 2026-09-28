using System.Net.Http;

public sealed class ArtifactJob(HttpClient httpClient)
{
    public async Task DownloadAsync(string url)
    {
        await httpClient.GetStreamAsync(url);
    }
}

public sealed class OtherClient
{
    public Task GetStreamAsync(string url) => Task.CompletedTask;
}

public sealed class ShadowedJob(HttpClient httpClient)
{
    public async Task DownloadAsync(string url, OtherClient httpClient)
    {
        await httpClient.GetStreamAsync(url);
    }
}
