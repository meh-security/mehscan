using Demo.Models;

namespace Demo.Controllers;

public sealed class TrackingController : Controller
{
    [HttpGet]
    public object Go(string carrier, string trackingNumber)
    {
        return Redirect(Tracker.GetUrl(carrier, trackingNumber));
    }
}
