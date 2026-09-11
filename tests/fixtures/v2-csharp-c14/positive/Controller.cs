using Microsoft.AspNetCore.Mvc;

public class SearchController : ControllerBase
{
    private readonly IQueryRepository _queries;
    private readonly IOrderService _orders;

    public SearchController(IQueryRepository queries, IOrderService orders)
    {
        _queries = queries;
        _orders = orders;
    }

    [HttpGet]
    public object UnsafeSql([FromQuery] string query) => _queries.UnsafeSql(query);

    [HttpGet]
    public object ParameterizedSql([FromQuery] string value) => _queries.ParameterizedSql(value);

    [HttpGet]
    public object UnscopedOrder([FromQuery] string id) => _orders.Unscoped(id);

    [HttpGet]
    public object ScopedOrder([FromQuery] string id) => _orders.Scoped(id);
}
