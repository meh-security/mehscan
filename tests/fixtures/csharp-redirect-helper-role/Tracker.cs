namespace Demo.Models;

public static class Tracker
{
    public static string GetUrl(string carrier, string trackingNumber)
    {
        if (carrier == "known")
        {
            return string.Format("https://tracking.example/lookup?id={0}", trackingNumber);
        }

        return string.Format("https://{0}/lookup?id={1}", carrier, trackingNumber);
    }
}
