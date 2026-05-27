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

    public OrdersController(DatabaseService db)
    {
        _db = db;
    }

    /// <summary>Купить товар — УЯЗВИМО к подделке цены и отрицательному количеству</summary>
    [HttpPost("purchase")]
    public IActionResult Purchase([FromBody] PurchaseRequest req)
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        var product = _db.GetProductById(req.ProductId);
        if (product == null) return NotFound(new { error = "Товар не найден" });

        // [VULN-6] Если клиент прислал свою цену — используем её!
        decimal price = req.ClientPrice.HasValue ? req.ClientPrice.Value : product.Price;

        // [VULN-6] Нет проверки: quantity > 0 и price > 0
        // Можно купить quantity = -1 → получить деньги на счёт
        // Можно прислать price = 0.01 → купить за копейки

        var order = _db.CreateOrder(userId, req.ProductId, req.Quantity, price);
        if (order == null) return BadRequest(new { error = "Не удалось создать заказ" });

        return Ok(new
        {
            message = "Заказ создан",
            order = new { order.Id, order.TotalPrice, order.Status }
        });
    }

    /// <summary>Мои заказы</summary>
    [HttpGet("my")]
    public IActionResult MyOrders()
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        return Ok(_db.GetOrdersByUserId(userId));
    }

    /// <summary>Получить заказ по ID — УЯЗВИМО к IDOR</summary>
    [HttpGet("{id}")]
    public IActionResult GetOrder(int id)
    {
        // [VULN-7] IDOR: не проверяем, что заказ принадлежит текущему пользователю
        // Любой авторизованный пользователь может получить чужой заказ по ID
        var order = _db.GetOrderById(id);
        if (order == null) return NotFound();
        return Ok(order);
    }

    /// <summary>Перевод средств — УЯЗВИМО к IDOR (можно перевести с чужого счёта)</summary>
    [HttpPost("transfer")]
    public IActionResult Transfer([FromBody] TransferRequest req)
    {
        // [VULN-7] IDOR: сервер не проверяет что req.FromUserId == текущий пользователь
        // Любой авторизованный пользователь может перевести деньги с чужого счёта
        if (req.Amount <= 0)
            return BadRequest(new { error = "Сумма должна быть больше нуля" });

        _db.Transfer(req.FromUserId, req.ToUserId, req.Amount);
        return Ok(new { message = $"Переведено {req.Amount} ₽ с аккаунта #{req.FromUserId} на #{req.ToUserId}" });
    }
}
