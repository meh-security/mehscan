using System.Diagnostics;

class Demo
{
    void Broken() { var value = ; }
    void Run(string command) { Process.Start(command); }
}
