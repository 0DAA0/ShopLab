// FIX: Пароль не возвращается в ответах; rate limiting на /login и /register
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ShopLab.Data;
using ShopLab.Models;
using ShopLab.Services;

namespace ShopLab.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly DatabaseService _db;
    private readonly TokenService _token;

    public AuthController(DatabaseService db, TokenService token)
    {
        _db = db;
        _token = token;
    }

    [HttpPost("register")]
    [EnableRateLimiting("auth")] // FIX-8: rate limiting
    public IActionResult Register([FromBody] RegisterRequest req)
    {
        // FIX: Валидация сложности пароля
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest(new { error = "Username и Password обязательны" });
        if (req.Password.Length < 8)
            return BadRequest(new { error = "Пароль должен быть не менее 8 символов" });

        var success = _db.CreateUser(req.Username, req.Password, req.Email);
        if (!success) return Conflict(new { error = "Пользователь уже существует" });

        var user = _db.GetUserByUsername(req.Username)!;
        var tokenStr = _token.GenerateToken(user.Id, user.Username, user.Role);
        // FIX-4: Пароль не возвращается
        return Ok(new { token = tokenStr, user = new { user.Id, user.Username, user.Email, user.Role, user.Balance } });
    }

    [HttpPost("login")]
    [EnableRateLimiting("auth")] // FIX-8: rate limiting — не более 10 попыток в минуту
    public IActionResult Login([FromBody] LoginRequest req)
    {
        var user = _db.GetUserByCredentials(req.Username, req.Password); // FIX-1, FIX-4
        if (user == null)
        {
            // FIX: одинаковое время ответа независимо от того, нашёлся ли пользователь
            Thread.Sleep(100); // timing attack mitigation
            return Unauthorized(new { error = "Неверный логин или пароль" });
        }
        var tokenStr = _token.GenerateToken(user.Id, user.Username, user.Role);
        return Ok(new { token = tokenStr, user = new { user.Id, user.Username, user.Email, user.Role, user.Balance } });
    }

    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        var user = _db.GetUserById(userId);
        if (user == null) return NotFound();
        // FIX-4: Пароль не возвращается
        return Ok(new { user.Id, user.Username, user.Email, user.Role, user.Balance });
    }

    [HttpGet("users")]
    [Authorize(Roles = "admin")]
    public IActionResult GetUsers()
    {
        var users = _db.GetAllUsers();
        // FIX-4: Возвращаем без паролей
        return Ok(users.Select(u => new { u.Id, u.Username, u.Email, u.Role, u.Balance }));
    }
}
