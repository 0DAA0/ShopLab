namespace ShopLab.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Password { get; set; } = ""; // [VULN-4] Хранится в открытом виде или MD5
    public string Email { get; set; } = "";
    public string Role { get; set; } = "user"; // "user" или "admin"
    public decimal Balance { get; set; } = 1000m;
}

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public decimal Price { get; set; }
    public int Stock { get; set; }
    public string ImageUrl { get; set; } = "";
}

public class Order
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public int ProductId { get; set; }
    public int Quantity { get; set; }
    public decimal TotalPrice { get; set; }
    public string Status { get; set; } = "pending";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    // Для JOIN-запросов
    public string? ProductName { get; set; }
    public string? Username { get; set; }
}

public class Review
{
    public int Id { get; set; }
    public int ProductId { get; set; }
    public int UserId { get; set; }
    public string Content { get; set; } = ""; // [VULN-2] XSS - содержимое не санируется
    public int Rating { get; set; }
    public string? Username { get; set; }
}

// DTO для запросов
public class RegisterRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Email { get; set; } = "";
}

public class LoginRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class PurchaseRequest
{
    public int ProductId { get; set; }
    public int Quantity { get; set; }
    // [VULN-6] Клиент может прислать свою цену
    public decimal? ClientPrice { get; set; }
}

public class ReviewRequest
{
    public int ProductId { get; set; }
    public string Content { get; set; } = "";
    public int Rating { get; set; }
}

public class TransferRequest
{
    public int FromUserId { get; set; }  // [VULN-7] IDOR - сервер не проверяет что это ваш счёт
    public int ToUserId { get; set; }
    public decimal Amount { get; set; }
}

public class SearchRequest
{
    public string Query { get; set; } = "";
}
