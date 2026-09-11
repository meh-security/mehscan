using System.Web.Mvc;

public class LegacyController : Controller
{
    [ValidateInput(false)]
    public ActionResult Accept(string content)
    {
        return View(content);
    }
}
