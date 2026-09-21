using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

public static class OrderEndpoints
{
    public static void MapOrderEndpoints(WebApplication app)
    {
        app.MapPatch("/orders/{id}/status", UnsafeTransitionAsync);
        app.MapPost("/orders/{id}/transitions", GuardedTransitionAsync);
    }

    private static async Task<IResult> UnsafeTransitionAsync(
        Guid id, UpdateOrderStatusRequest request, OrdersDbContext db)
    {
        var order = await db.Orders.FindAsync(id);
        if (order is null) return Results.NotFound();
        order.Status = request.TargetStatus;
        await db.SaveChangesAsync();
        return Results.Ok(order);
    }

    private static async Task<IResult> GuardedTransitionAsync(
        Guid id, UpdateOrderStatusRequest request, OrderService service)
    {
        return Results.Ok(await service.AdvanceAsync(id, request.TargetStatus));
    }
}

public sealed record UpdateOrderStatusRequest(OrderStatus TargetStatus);

public sealed class OrderService(OrdersDbContext db)
{
    public async Task<Order> AdvanceAsync(Guid id, OrderStatus target)
    {
        var order = await db.Orders.FindAsync(id) ?? throw new InvalidOperationException();
        order.AdvanceTo(target);
        await db.SaveChangesAsync();
        return order;
    }
}

public sealed class Order
{
    public Guid Id { get; set; }
    public OrderStatus Status { get; private set; }

    public void AdvanceTo(OrderStatus target)
    {
        switch (target)
        {
            case OrderStatus.Approved when Status == OrderStatus.Pending:
                Status = OrderStatus.Approved;
                break;
            case OrderStatus.Shipped when Status == OrderStatus.Approved:
                Status = OrderStatus.Shipped;
                break;
            default:
                throw new InvalidOperationException("Transition is not allowed");
        }
    }
}

public enum OrderStatus { Pending, Approved, Shipped }

public sealed class OrdersDbContext : DbContext
{
    public DbSet<Order> Orders => Set<Order>();
}
