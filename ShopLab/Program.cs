// ======================================================
// VULNERABLE VERSION - ветка: vulnerable
// Намеренно содержит уязвимости для учебных целей!
// ======================================================

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ShopLab.Data;
using ShopLab.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// [VULN-5] Секретный ключ JWT прямо в коде (hardcoded secret)
var jwtSecret = "secret123"; // УЯЗВИМОСТЬ: слабый и захардкоженный секрет

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "ShopLab API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Введите JWT токен",
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "bearer"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            // [VULN-3] Нет проверки времени жизни токена
            ValidateLifetime = false
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddSingleton<TokenService>(sp => new TokenService(jwtSecret));

// [VULN] CORS разрешён для всех origin
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

var app = builder.Build();

// Инициализация БД
var db = app.Services.GetRequiredService<DatabaseService>();
db.Initialize();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "ShopLab API v1");
    c.RoutePrefix = "swagger";
});

app.UseStaticFiles();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Перенаправление корня на фронтенд
app.MapGet("/", () => Results.Redirect("/index.html"));

app.Run();
