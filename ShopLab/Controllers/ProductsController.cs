using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ShopLab.Data;
using ShopLab.Models;

namespace ShopLab.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    private readonly DatabaseService _db;

    public ProductsController(DatabaseService db)
    {
        _db = db;
    }

    /// <summary>Получить все товары</summary>
    [HttpGet]
    public IActionResult GetAll() => Ok(_db.GetAllProducts());

    /// <summary>Получить товар по ID</summary>
    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        var product = _db.GetProductById(id);
        if (product == null) return NotFound();
        return Ok(product);
    }

    /// <summary>Поиск товаров — УЯЗВИМО к SQL Injection</summary>
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string q = "")
    {
        // [VULN-1] SQL Injection через параметр q
        // Пример атаки: ?q=' UNION SELECT 1,Username,Password,Email,Role,Balance FROM Users--
        var products = _db.SearchProducts(q);
        return Ok(products);
    }

    /// <summary>Получить отзывы на товар — УЯЗВИМО к XSS</summary>
    [HttpGet("{id}/reviews")]
    public IActionResult GetReviews(int id)
    {
        // [VULN-2] Content возвращается без санитизации — XSS при рендеринге
        var reviews = _db.GetReviewsByProductId(id);
        return Ok(reviews);
    }

    /// <summary>Добавить отзыв — УЯЗВИМО к Stored XSS</summary>
    [HttpPost("reviews")]
    [Authorize]
    public IActionResult AddReview([FromBody] ReviewRequest req)
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        // [VULN-2] Content не фильтруется от HTML/JS тегов
        _db.AddReview(req.ProductId, userId, req.Content, req.Rating);
        return Ok(new { message = "Отзыв добавлен" });
    }
}
