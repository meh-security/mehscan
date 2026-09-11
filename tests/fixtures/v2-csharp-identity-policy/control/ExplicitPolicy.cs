using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

public class ExplicitPolicyStartup
{
    public void Configure(IServiceCollection services, WebApplication app)
    {
        services.AddAuthentication().AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                RequireExpirationTime = true
            };
        });

        services.AddAuthentication().AddCookie(options =>
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });

        services.AddCors(options => options.AddPolicy("browser", policy =>
            policy.WithOrigins("https://portal.example").AllowCredentials()));

        services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        });

        var forwarded = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                               ForwardedHeaders.XForwardedProto
        };
        forwarded.KnownProxies.Add(IPAddress.Parse("10.0.0.10"));

        app.UseForwardedHeaders(forwarded);
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();
        app.MapPost("/transfer", () => "ok").RequireAntiforgery();
    }
}

public class ExplicitPolicyController : ControllerBase
{
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "account-owner")]
    public IActionResult ChangeEmail() => Ok();
}
