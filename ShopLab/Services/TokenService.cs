using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ShopLab.Services;

public class TokenService
{
    private readonly string _secret;

    public TokenService(string secret)
    {
        _secret = secret;
    }

    // [VULN-5] Токен не истекает (нет expiry), секрет слабый
    public string GenerateToken(int userId, string username, string role)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim("userId", userId.ToString()),
            new Claim("username", username),
            new Claim(ClaimTypes.Role, role),
            // [VULN-3] Нет поля exp — токен вечный
        };

        var token = new JwtSecurityToken(
            claims: claims,
            signingCredentials: creds
            // expires: не указан — токен не истекает!
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_secret);
        try
        {
            return tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false // [VULN-3] Не проверяем время жизни
            }, out _);
        }
        catch { return null; }
    }
}
