using System.IO;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

public class UploadPage : Page
{
    public void Store(FileUpload uploadFile)
    {
        File.WriteAllBytes(
            @"C:\uploads\" + uploadFile.PostedFile.FileName,
            uploadFile.FileBytes);
    }

    public void StorePostedFile(HttpPostedFile upload, string destination)
    {
        upload.SaveAs(destination);
    }
}
