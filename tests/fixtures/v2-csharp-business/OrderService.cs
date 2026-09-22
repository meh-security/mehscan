using Microsoft.EntityFrameworkCore;

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
