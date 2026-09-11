using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

public class WeakPolicyStartup
{
    public void Configure(IServiceCollection services, WebApplication app)
    {
        services.AddAuthentication().AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
                RequireSignedTokens = false
            };
        });

        services.AddAuthentication().AddCookie(options =>
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.None;
            options.Cookie.HttpOnly = false;
            options.Cookie.SameSite = SameSiteMode.None;
        });

        services.AddCors(options => options.AddPolicy("weak", policy =>
            policy.SetIsOriginAllowed(_ => true).AllowCredentials()));

        services.AddAuthorization(options => options.FallbackPolicy = null);

        var forwarded = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                               ForwardedHeaders.XForwardedProto
        };
        forwarded.KnownNetworks.Clear();
        forwarded.KnownProxies.Clear();

        app.UseAuthorization();
        app.UseAuthentication();
        app.UseForwardedHeaders(forwarded);
        app.MapControllers();
        app.MapPost("/transfer", () => "ok").DisableAntiforgery();
        app.MapDelete("/account", () => "deleted").AllowAnonymous();
    }
}

public class WeakPolicyController : ControllerBase
{
    [HttpPost]
    [IgnoreAntiforgeryToken]
    public IActionResult ChangeEmail() => Ok();

    [HttpDelete]
    [AllowAnonymous]
    public IActionResult DeleteAccount() => Ok();
}
