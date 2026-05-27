// ======================================================
// FIXED VERSION — ветка: fixed
// Все уязвимости исправлены
// ======================================================

using Microsoft.Data.Sqlite;
using ShopLab.Models;
using System.Security.Cryptography;
using System.Text;

namespace ShopLab.Data;

public class DatabaseService
{
    private readonly string _connectionString = "Data Source=shoplab.db";

    public void Initialize()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Password TEXT NOT NULL,
                Email TEXT NOT NULL,
                Role TEXT NOT NULL DEFAULT 'user',
                Balance REAL NOT NULL DEFAULT 1000.0
            );
            CREATE TABLE IF NOT EXISTS Products (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Name TEXT NOT NULL,
                Description TEXT NOT NULL,
                Price REAL NOT NULL,
                Stock INTEGER NOT NULL DEFAULT 0,
                ImageUrl TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS Orders (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UserId INTEGER NOT NULL,
                ProductId INTEGER NOT NULL,
                Quantity INTEGER NOT NULL,
                TotalPrice REAL NOT NULL,
                Status TEXT NOT NULL DEFAULT 'pending',
                CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(UserId) REFERENCES Users(Id),
                FOREIGN KEY(ProductId) REFERENCES Products(Id)
            );
            CREATE TABLE IF NOT EXISTS Reviews (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                ProductId INTEGER NOT NULL,
                UserId INTEGER NOT NULL,
                Content TEXT NOT NULL,
                Rating INTEGER NOT NULL,
                FOREIGN KEY(ProductId) REFERENCES Products(Id),
                FOREIGN KEY(UserId) REFERENCES Users(Id)
            );
        ";
        cmd.ExecuteNonQuery();
        SeedData(conn);
    }

    private void SeedData(SqliteConnection conn)
    {
        var checkCmd = conn.CreateCommand();
        checkCmd.CommandText = "SELECT COUNT(*) FROM Users";
        var count = (long)(checkCmd.ExecuteScalar() ?? 0L);
        if (count > 0) return;

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO Users (Username, Password, Email, Role, Balance) VALUES
                ('admin', @adminPass, 'admin@shoplab.local', 'admin', 9999.0),
                ('alice', @alicePass, 'alice@example.com', 'user', 1000.0),
                ('bob',   @bobPass,   'bob@example.com',   'user', 500.0);
            INSERT INTO Products (Name, Description, Price, Stock, ImageUrl) VALUES
                ('Ноутбук Pro X',     'Мощный ноутбук для работы и игр',   49999.0, 10, '/img/laptop.png'),
                ('Смартфон Alpha',    'Флагманский смартфон 2024',          29999.0, 25, '/img/phone.png'),
                ('Наушники SoundMax', 'Беспроводные наушники с ANC',        4999.0,  50, '/img/headphones.png'),
                ('Планшет Tab 10',    '10-дюймовый планшет для учёбы',      15999.0, 15, '/img/tablet.png'),
                ('Мышь GamerX',       'Игровая мышь с RGB подсветкой',      2499.0,  100, '/img/mouse.png');
        ";
        // FIX-4: используем PBKDF2 (bcrypt-подобный), а не MD5
        cmd.Parameters.AddWithValue("@adminPass", HashPassword("admin123"));
        cmd.Parameters.AddWithValue("@alicePass", HashPassword("alice123"));
        cmd.Parameters.AddWithValue("@bobPass",   HashPassword("bob123"));
        cmd.ExecuteNonQuery();
    }

    // FIX-4: PBKDF2 с солью вместо MD5
    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }

    public static bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split(':');
        if (parts.Length != 2) return false;
        var salt = Convert.FromBase64String(parts[0]);
        var expectedHash = Convert.FromBase64String(parts[1]);
        var actualHash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    // FIX-1: Параметризованный запрос — SQL injection невозможен
    public List<Product> SearchProducts(string query)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Products WHERE Name LIKE @q OR Description LIKE @q";
        cmd.Parameters.AddWithValue("@q", $"%{query}%");
        var products = new List<Product>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) products.Add(MapProduct(reader));
        return products;
    }

    public User? GetUserByCredentials(string username, string password)
    {
        // FIX-1: Параметризованный запрос; FIX-4: проверка через PBKDF2
        var user = GetUserByUsername(username);
        if (user == null) return null;
        return VerifyPassword(password, user.Password) ? user : null;
    }

    public User? GetUserById(int id)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Users WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        if (reader.Read()) return MapUser(reader);
        return null;
    }

    public User? GetUserByUsername(string username)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Users WHERE Username = @u";
        cmd.Parameters.AddWithValue("@u", username);
        using var reader = cmd.ExecuteReader();
        if (reader.Read()) return MapUser(reader);
        return null;
    }

    public bool CreateUser(string username, string password, string email)
    {
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO Users (Username, Password, Email) VALUES (@u, @p, @e)";
            cmd.Parameters.AddWithValue("@u", username);
            cmd.Parameters.AddWithValue("@p", HashPassword(password)); // FIX-4
            cmd.Parameters.AddWithValue("@e", email);
            cmd.ExecuteNonQuery();
            return true;
        }
        catch { return false; }
    }

    public List<Product> GetAllProducts()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Products";
        var products = new List<Product>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) products.Add(MapProduct(reader));
        return products;
    }

    public Product? GetProductById(int id)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Products WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        if (reader.Read()) return MapProduct(reader);
        return null;
    }

    // FIX-6: Цена берётся ТОЛЬКО из БД; проверка qty > 0; проверка баланса
    public (Order? order, string? error) CreateOrder(int userId, int productId, int quantity)
    {
        if (quantity <= 0) return (null, "Количество должно быть больше нуля");

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        var user = GetUserById(userId);
        var product = GetProductById(productId);
        if (user == null) return (null, "Пользователь не найден");
        if (product == null) return (null, "Товар не найден");
        if (product.Stock < quantity) return (null, "Недостаточно товара на складе");

        decimal totalPrice = product.Price * quantity; // FIX-6: серверная цена
        if (user.Balance < totalPrice) return (null, "Недостаточно средств");

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE Users SET Balance = Balance - @total WHERE Id = @userId;
            UPDATE Products SET Stock = Stock - @qty WHERE Id = @productId;
            INSERT INTO Orders (UserId, ProductId, Quantity, TotalPrice, Status)
            VALUES (@userId, @productId, @qty, @total, 'completed');
            SELECT last_insert_rowid();
        ";
        cmd.Parameters.AddWithValue("@total", totalPrice);
        cmd.Parameters.AddWithValue("@userId", userId);
        cmd.Parameters.AddWithValue("@productId", productId);
        cmd.Parameters.AddWithValue("@qty", quantity);
        var orderId = (long)(cmd.ExecuteScalar() ?? 0L);
        return (new Order { Id = (int)orderId, UserId = userId, ProductId = productId, Quantity = quantity, TotalPrice = totalPrice, Status = "completed" }, null);
    }

    // FIX-7: принимает currentUserId и проверяет принадлежность
    public (bool success, string? error) Transfer(int currentUserId, int fromUserId, int toUserId, decimal amount)
    {
        if (currentUserId != fromUserId)
            return (false, "Нельзя переводить деньги с чужого счёта"); // FIX-7: IDOR fix
        if (amount <= 0) return (false, "Сумма должна быть больше нуля");

        var from = GetUserById(fromUserId);
        if (from == null || from.Balance < amount) return (false, "Недостаточно средств");

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE Users SET Balance = Balance - @amount WHERE Id = @from;
            UPDATE Users SET Balance = Balance + @amount WHERE Id = @to;
        ";
        cmd.Parameters.AddWithValue("@amount", amount);
        cmd.Parameters.AddWithValue("@from", fromUserId);
        cmd.Parameters.AddWithValue("@to", toUserId);
        cmd.ExecuteNonQuery();
        return (true, null);
    }

    public List<Order> GetOrdersByUserId(int userId)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT o.*, p.Name as ProductName, u.Username
            FROM Orders o JOIN Products p ON o.ProductId = p.Id JOIN Users u ON o.UserId = u.Id
            WHERE o.UserId = @userId";
        cmd.Parameters.AddWithValue("@userId", userId);
        var orders = new List<Order>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            orders.Add(new Order { Id = reader.GetInt32(0), UserId = reader.GetInt32(1), ProductId = reader.GetInt32(2), Quantity = reader.GetInt32(3), TotalPrice = reader.GetDecimal(4), Status = reader.GetString(5), ProductName = reader.IsDBNull(7) ? null : reader.GetString(7) });
        return orders;
    }

    // FIX-7: GetOrderById теперь требует userId для проверки принадлежности
    public Order? GetOrderById(int orderId, int userId)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT o.*, p.Name as ProductName, u.Username FROM Orders o
            JOIN Products p ON o.ProductId = p.Id JOIN Users u ON o.UserId = u.Id
            WHERE o.Id = @id AND o.UserId = @userId"; // FIX-7: проверяем владельца
        cmd.Parameters.AddWithValue("@id", orderId);
        cmd.Parameters.AddWithValue("@userId", userId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return new Order { Id = reader.GetInt32(0), UserId = reader.GetInt32(1), ProductId = reader.GetInt32(2), Quantity = reader.GetInt32(3), TotalPrice = reader.GetDecimal(4), Status = reader.GetString(5), ProductName = reader.IsDBNull(7) ? null : reader.GetString(7) };
    }

    // FIX-2: Content сохраняется после HTML-кодирования (хранится как plain text)
    public void AddReview(int productId, int userId, string content, int rating)
    {
        var safeContent = System.Net.WebUtility.HtmlEncode(content); // FIX-2: XSS prevention
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Reviews (ProductId, UserId, Content, Rating) VALUES (@pid, @uid, @c, @r)";
        cmd.Parameters.AddWithValue("@pid", productId);
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.Parameters.AddWithValue("@c", safeContent);
        cmd.Parameters.AddWithValue("@r", rating);
        cmd.ExecuteNonQuery();
    }

    public List<Review> GetReviewsByProductId(int productId)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT r.*, u.Username FROM Reviews r JOIN Users u ON r.UserId = u.Id WHERE r.ProductId = @pid";
        cmd.Parameters.AddWithValue("@pid", productId);
        var reviews = new List<Review>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            reviews.Add(new Review { Id = reader.GetInt32(0), ProductId = reader.GetInt32(1), UserId = reader.GetInt32(2), Content = reader.GetString(3), Rating = reader.GetInt32(4), Username = reader.IsDBNull(5) ? null : reader.GetString(5) });
        return reviews;
    }

    public List<User> GetAllUsers()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM Users";
        var users = new List<User>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) users.Add(MapUser(reader));
        return users;
    }

    private static Product MapProduct(SqliteDataReader r) => new() { Id = r.GetInt32(0), Name = r.GetString(1), Description = r.GetString(2), Price = r.GetDecimal(3), Stock = r.GetInt32(4), ImageUrl = r.GetString(5) };
    private static User MapUser(SqliteDataReader r) => new() { Id = r.GetInt32(0), Username = r.GetString(1), Password = r.GetString(2), Email = r.GetString(3), Role = r.GetString(4), Balance = r.GetDecimal(5) };
}
