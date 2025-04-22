using JwtCookieAuthApi.Data;
using JwtCookieAuthApi.Models;
using JwtCookieAuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 🔐 Configurações JWT
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

// 📦 Serviços
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<TokenService>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!))
    };

    // 🍪 Lê o token do cookie
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            if (context.Request.Cookies.ContainsKey("jwtToken"))
            {
                context.Token = context.Request.Cookies["jwtToken"];
            }
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// 🔧 Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

// ✅ Registro
app.MapPost("/register", async (User user, AppDbContext db) =>
{
    var exists = await db.Users.AnyAsync(u => u.Username == user.Username);
    if (exists)
        return Results.BadRequest("Usuário já existe");

    user.Id = Guid.NewGuid();
    await db.Users.AddAsync(user);
    await db.SaveChangesAsync();

    return Results.Ok("Usuário registrado com sucesso");
});

// 🔐 Login
app.MapPost("/login", async (LoginRequest login, AppDbContext db, TokenService tokenService, HttpResponse response) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u =>
        u.Username == login.Username && u.Password == login.Password);

    if (user is null)
        return Results.Unauthorized();

    var token = tokenService.GenerateToken(user);

    response.Cookies.Append("jwtToken", token, new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Expires = DateTimeOffset.UtcNow.AddHours(1)
    });

    return Results.Ok("Login realizado com sucesso");
});

app.MapPost("/logout", (HttpResponse response) =>
{
    response.Cookies.Delete("jwtToken");

    return Results.Ok("Logout realizado com sucesso");
});

// 🔒 Endpoint protegido
app.MapGet("/me", (ClaimsPrincipal user) =>
{
    var username = user.FindFirst("username")?.Value;
    var userId = user.FindFirst("userId")?.Value;

    return Results.Ok(new
    {
        Authenticated = true,
        Username = username,
        UserId = userId
    });
})
.RequireAuthorization();

app.Run();
