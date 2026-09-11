public sealed class LoginInput
{
    public string ReturnUrl { get; set; }
}

public sealed class RedirectPrecisionController : Controller
{
    [HttpPost]
    public object Unsafe(LoginInput model)
    {
        if (model.ReturnUrl != null)
        {
            return Redirect(model.ReturnUrl);
        }
        return View();
    }

    [HttpPost]
    public object Guarded(LoginInput model)
    {
        if (Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }
        return View();
    }

    [HttpGet]
    public object Generated(string tenant)
    {
        return Redirect(Url.Action(nameof(Generated), new { tenant }));
    }

    [HttpGet]
    public object GeneratedByHelper(string tenant)
    {
        return Redirect(GetLocalUrl(tenant));
    }

    [HttpPost]
    public object Lookalike(LoginInput model)
    {
        if (CustomUrl.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }
        return View();
    }

    [HttpPost]
    public object TerminatingGuard(LoginInput model)
    {
        if (!Url.IsLocalUrl(model.ReturnUrl))
        {
            return View();
        }
        return Redirect(model.ReturnUrl);
    }

    public object Conventional(LoginInput model)
    {
        if (!string.IsNullOrWhiteSpace(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }
        return View();
    }

    private string GetLocalUrl(string tenant)
    {
        if (tenant == "admin")
        {
            return Url.Action(nameof(Generated));
        }
        return Url.Content("~/" + tenant);
    }
}

public static class CustomUrl
{
    public static bool IsLocalUrl(string value) => true;
}
