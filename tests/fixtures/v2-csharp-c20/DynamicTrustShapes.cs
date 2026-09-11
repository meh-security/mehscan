using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;

public class User
{
    public int ID { get; set; }
    public int OwnerId { get; set; }
    public string createAccessToken() => "token";
}

public class AppDb : DbContext
{
    public DbSet<User> Users { get; set; }
}

public class ImportsController : Controller
{
    [HttpPost]
    public IActionResult VulnerableImport()
    {
        var document = new XmlDocument();
        document.Load(HttpContext.Request.Body);
        foreach (XmlElement item in document.SelectNodes("Entities/Entity"))
        {
            string typeName = item.GetAttribute("Type");
            var serializer = new XmlSerializer(Type.GetType(typeName));
            serializer.Deserialize(new StringReader(item.InnerXml));
        }
        return Ok();
    }

    [HttpPost]
    public IActionResult AllowlistedImport()
    {
        var document = new XmlDocument();
        document.Load(HttpContext.Request.Body);
        foreach (XmlElement item in document.SelectNodes("Entities/Entity"))
        {
            string typeName = item.GetAttribute("Type");
            if (typeName != "AllowedMessage")
                return BadRequest();
            var serializer = new XmlSerializer(Type.GetType(typeName));
            serializer.Deserialize(new StringReader(item.InnerXml));
        }
        return Ok();
    }

    public object TypedImport(Stream input)
    {
        var serializer = new XmlSerializer(typeof(User));
        return serializer.Deserialize(input);
    }
}

public class AuthorizationsController : Controller
{
    private readonly AppDb _context;
    private readonly IDataProtector _protector;

    [HttpGet]
    public IActionResult VulnerableSso()
    {
        var cookieData = HttpContext.Request.Cookies["sso_ctx"];
        var decoded = Convert.FromBase64String(cookieData);
        var cookie = JObject.Parse(Encoding.UTF8.GetString(decoded));
        var userId = cookie["auth_user"];
        var user = _context.Users.SingleOrDefault(x => x.ID == userId.ToObject<int>());
        return Ok(user.createAccessToken());
    }

    [HttpGet]
    public IActionResult ProtectedSso()
    {
        var cookieData = HttpContext.Request.Cookies["sso_ctx"];
        var protectedValue = _protector.Unprotect(cookieData);
        var decoded = Convert.FromBase64String(protectedValue);
        var cookie = JObject.Parse(Encoding.UTF8.GetString(decoded));
        var userId = cookie["auth_user"];
        var user = _context.Users.SingleOrDefault(x => x.ID == userId.ToObject<int>());
        return Ok(user.createAccessToken());
    }

    [Authorize]
    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        var user = _context.Users.SingleOrDefault(x => x.ID == id);
        _context.Users.Remove(user);
        return Ok();
    }

    [Authorize]
    [HttpDelete("safe/{id}")]
    public IActionResult DeleteOwned(int id)
    {
        var user = _context.Users.SingleOrDefault(x => x.ID == id && x.OwnerId == User.Identity.Name);
        _context.Users.Remove(user);
        return Ok();
    }
}
