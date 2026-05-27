// FIX-3: Токен с временем жизни; FIX-5: секрет из env
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ShopLab.Services;

public class TokenService
{
    private readonly string _secret;

    public TokenService(string secret) { _secret = secret; }

    // FIX-3: Токен истекает через 1 час
    // FIX-5: Используется сильный секрет из переменной окружения
    public string GenerateToken(int userId, string username, string role)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim("userId", userId.ToString()),
            new Claim("username", username),
            new Claim(ClaimTypes.Role, role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: "shoplab",
            audience: "shoplab-users",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1), // FIX-3: срок жизни
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
