using System;
using System.IO;

class Paths
{
    void NamedCopy() { File.Copy(destFileName: "known.txt", sourceFileName: Console.ReadLine()); }
    void NamedMove() { File.Move(destFileName: Console.ReadLine(), sourceFileName: "known.txt"); }
    void NamedDirectoryMove() { Directory.Move(destDirName: Console.ReadLine(), sourceDirName: "known"); }
    void NamedStream() { using (var stream = new FileStream(mode: FileMode.Create, path: Console.ReadLine())) {} }
}
