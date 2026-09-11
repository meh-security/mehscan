using System;
using System.IO;
using System.Linq;
using Microsoft.EntityFrameworkCore;

public class FilesystemPositive
{
    public string Read()
    {
        return File.ReadAllText(Console.ReadLine());
    }

    public void Write()
    {
        File.WriteAllText(System.Console.ReadLine(), "content");
    }
}

public class LegacyEfPositive
{
    public void Query()
    {
        using (var context = new StudentContext())
        {
            context.Students
                .FromSql("SELECT * FROM Students WHERE Name = '" + Console.ReadLine() + "'")
                .ToList();
            context.Database.ExecuteSqlCommand(
                "DELETE FROM Students WHERE Name = '" + Console.ReadLine() + "'");
        }
    }
}

public class StudentContext : DbContext
{
    public DbSet<Student> Students { get; set; }
}

public class Student
{
}
