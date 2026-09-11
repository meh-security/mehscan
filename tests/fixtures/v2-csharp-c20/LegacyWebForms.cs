using System;
using System.Web;
using System.Web.UI;

public class LegacyPage : Page
{
    public void Page_Load(object sender, EventArgs e)
    {
        string url = HttpContext.Current.Request.Params["includedURL"];
        Page.ClientScript.RegisterClientScriptInclude("remote", url);

        HttpPostedFile upload = Request.Files[0];
        var content = upload.InputStream;
    }
}
