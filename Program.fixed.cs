// ======================================================
// FIXED VERSION — ветка: fixed
// ======================================================

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ShopLab.Data;
using ShopLab.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// FIX-5: Секрет берётся из переменной окружения, не из кода
// Запуск: JWT_SECRET="your-strong-secret-here-min-32-chars" dotnet run
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")
    ?? throw new InvalidOperationException("JWT_SECRET environment variable is required");

if (jwtSecret.Length < 32)
    throw new InvalidOperationException("JWT_SECRET must be at least 32 characters");

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "ShopLab API (Fixed)", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "bearer"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {{
        new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Reference = new Microsoft.OpenApi.Models.OpenApiReference
            { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" }
        },
        Array.Empty<string>()
    }});
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ValidateIssuer = true,
            ValidIssuer = "shoplab",
            ValidateAudience = true,
            ValidAudience = "shoplab-users",
            ValidateLifetime = true, // FIX-3: проверяем срок жизни токена
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddSingleton<TokenService>(sp => new TokenService(jwtSecret));

// FIX: CORS только для конкретного origin
builder.Services.AddCors(options =>
{
    options.AddPolicy("Local", policy =>
        policy.WithOrigins("http://localhost:5000", "https://localhost:5001")
              .AllowAnyMethod()
              .AllowAnyHeader());
});

// FIX-8: Rate limiting (требует .NET 7+)
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("auth", o =>
    {
        o.PermitLimit = 10;
        o.Window = TimeSpan.FromMinutes(1);
        o.QueueLimit = 0;
    });
});

var app = builder.Build();

var db = app.Services.GetRequiredService<DatabaseService>();
db.Initialize();

app.UseSwagger();
app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "ShopLab API (Fixed)"); c.RoutePrefix = "swagger"; });

app.UseStaticFiles();
app.UseCors("Local");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapGet("/", () => Results.Redirect("/index.html"));

app.Run();
