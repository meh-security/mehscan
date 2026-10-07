using System.Diagnostics;
using System.IO;

class Operations
{
    void Copy(string source, string destination)
    {
        File.Copy(source, destination);
        File.Copy(source, destination, true);
        // Equal operand text must not merge the distinct read and write roles.
        File.Copy(source, source);
        File.Move(source, destination);
        File.ReadAllText(source);
    }

    void Start(string executable, string arguments, ProcessStartInfo unknown)
    {
        var info = new ProcessStartInfo(executable, arguments) { UseShellExecute = false };
        Process.Start(info);
        Process.Start(info);
        Process.Start(new ProcessStartInfo(executable, arguments) { UseShellExecute = true });
        // No descriptor definition: the generic observation remains necessary.
        Process.Start(unknown);
        Process.Start(executable, arguments);
        // A non-admitted fixed-executable companion must not consume this job.
        Process.Start(new ProcessStartInfo("chmod", arguments) { UseShellExecute = false });
    }
}
