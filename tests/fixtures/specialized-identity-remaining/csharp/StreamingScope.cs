using System.IO;
using Microsoft.AspNetCore.Mvc;

[ApiController]
class StreamingScope : ControllerBase
{
    dynamic destination;

    void Store()
    {
        {
            FileStream destination = null;
        }
        Request.Body.CopyTo(destination);
    }
}
