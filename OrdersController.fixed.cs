// FIX-6: Цена только серверная; FIX-7: IDOR fix
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ShopLab.Data;
using ShopLab.Models;

namespace ShopLab.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class OrdersController : ControllerBase
{
    private readonly DatabaseService _db;
    public OrdersController(DatabaseService db) { _db = db; }

    [HttpPost("purchase")]
    public IActionResult Purchase([FromBody] PurchaseRequest req)
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        // FIX-6: ClientPrice полностью игнорируется — цена берётся из БД
        var (order, error) = _db.CreateOrder(userId, req.ProductId, req.Quantity);
        if (order == null) return BadRequest(new { error });
        return Ok(new { message = "Заказ создан", order = new { order.Id, order.TotalPrice, order.Status } });
    }

    [HttpGet("my")]
    public IActionResult MyOrders()
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        return Ok(_db.GetOrdersByUserId(userId));
    }

    [HttpGet("{id}")]
    public IActionResult GetOrder(int id)
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        // FIX-7: передаём userId — сервер проверит принадлежность в SQL
        var order = _db.GetOrderById(id, userId);
        if (order == null) return NotFound(new { error = "Заказ не найден или у вас нет доступа" });
        return Ok(order);
    }

    [HttpPost("transfer")]
    public IActionResult Transfer([FromBody] TransferRequest req)
    {
        var currentUserId = int.Parse(User.FindFirst("userId")!.Value);
        // FIX-7: передаём currentUserId — внутри проверяется совпадение с fromUserId
        var (success, error) = _db.Transfer(currentUserId, req.FromUserId, req.ToUserId, req.Amount);
        if (!success) return BadRequest(new { error });
        return Ok(new { message = $"Переведено {req.Amount} ₽" });
    }
}
