class SqlFlow
{
    object Direct(dynamic Request)
    {
        return new SqlCommand(Request.Query["direct"]);
    }

    void Propagated(dynamic Request)
    {
        var query = Request.Query["propagated"];
        var queryAlias = query;
        new SqlCommand(queryAlias);
    }
}
