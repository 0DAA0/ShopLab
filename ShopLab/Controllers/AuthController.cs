using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

    /// <summary>Регистрация нового пользователя</summary>
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest req)
    {
        // [VULN-8] Нет rate limiting — можно спамить регистрации
        // [VULN] Нет валидации сложности пароля
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest(new { error = "Username и Password обязательны" });

        var success = _db.CreateUser(req.Username, req.Password, req.Email);
        if (!success)
            return Conflict(new { error = "Пользователь уже существует" });

        var user = _db.GetUserByUsername(req.Username)!;
        var tokenStr = _token.GenerateToken(user.Id, user.Username, user.Role);

        return Ok(new
        {
            token = tokenStr,
            user = new { user.Id, user.Username, user.Email, user.Role, user.Balance }
        });
    }

    /// <summary>Вход в систему</summary>
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        // [VULN-8] Нет rate limiting — можно брутфорсить пароли бесконечно
        // [VULN-1] GetUserByCredentials уязвим к SQL injection
        var user = _db.GetUserByCredentials(req.Username, req.Password);

        if (user == null)
            return Unauthorized(new { error = "Неверный логин или пароль" });

        var tokenStr = _token.GenerateToken(user.Id, user.Username, user.Role);

        return Ok(new
        {
            token = tokenStr,
            user = new { user.Id, user.Username, user.Email, user.Role, user.Balance }
        });
    }

    /// <summary>Получить профиль текущего пользователя</summary>
    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        var userId = int.Parse(User.FindFirst("userId")!.Value);
        var user = _db.GetUserById(userId);
        if (user == null) return NotFound();

        // [VULN-4] Возвращаем хеш пароля в ответе!
        return Ok(new { user.Id, user.Username, user.Email, user.Role, user.Balance, user.Password });
    }

    /// <summary>[ADMIN] Получить всех пользователей с паролями</summary>
    [HttpGet("users")]
    [Authorize(Roles = "admin")]
    public IActionResult GetUsers()
    {
        var users = _db.GetAllUsers();
        // [VULN-4] Возвращаем все пароли (хеши) всем adminам
        return Ok(users);
    }
}
