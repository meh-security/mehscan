using System.IO;

public class FileUpload
{
    public byte[] FileBytes { get; set; }
    public string FileName { get; set; }
    public void SaveAs(string path) { }
}

public class LocalStorage
{
    public void Store(FileUpload upload)
    {
        File.WriteAllBytes(upload.FileName, upload.FileBytes);
        upload.SaveAs(upload.FileName);
    }
}
