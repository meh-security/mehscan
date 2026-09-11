using Microsoft.EntityFrameworkCore;

public class ResourceContext : DbContext
{
    public DbSet<ResourceRecord> Records { get; set; }
}

public class ResourceRecord
{
    public int Id { get; set; }
}

public class EfLookups
{
    private readonly ResourceContext _db;

    public ResourceRecord FixedRecord()
    {
        return _db.Records.FirstOrDefault(record => record.Id == 1);
    }

    public ResourceRecord DynamicRecord(int id)
    {
        return _db.Records.FirstOrDefault(record => record.Id == id);
    }
}
