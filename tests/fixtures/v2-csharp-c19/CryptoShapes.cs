using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

public class PasswordResetsController : Controller
{
    [HttpPost]
    public IActionResult Post([FromBody] ResetInput passwordResetRequest)
    {
        var md5 = MD5.Create();
        var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(passwordResetRequest.Email));
        return Ok(hash);
    }
}

public class ResetInput
{
    public string Email { get; set; }
}

public class UserTokenService
{
    private const string TokenSecret = "fixture-signing-secret-value";

    public string HashPassword(string password)
    {
        var md5 = MD5.Create();
        return System.Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }

    public SigningCredentials Credentials()
    {
        string secret = TokenSecret;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    public byte[] FileChecksum(byte[] contents)
    {
        var md5 = MD5.Create();
        return md5.ComputeHash(contents);
    }
}
