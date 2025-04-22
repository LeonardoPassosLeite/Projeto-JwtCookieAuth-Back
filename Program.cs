using JwtCookieAuthApi.Data;
using JwtCookieAuthApi.Models;
using JwtCookieAuthApi.Services;
using JwtCookieAuthApi.Services.IServices;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<ITokenService,TokenService>();
builder.Services.AddScoped<ICookieService, CookieService>();

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

Console.WriteLine($"🌍 Ambiente ativo: {builder.Environment.EnvironmentName}");

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (User user, AppDbContext db) =>
{
    var exists = await db.Users.AnyAsync(u => u.Username == user.Username);
    if (exists)
        return Results.BadRequest("Usuário já existe");

    user.Id = Guid.NewGuid();
    user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);

    await db.Users.AddAsync(user);
    await db.SaveChangesAsync();

    return Results.Ok("Usuário registrado com sucesso");
});

app.MapPost("/login", async (LoginRequest login, AppDbContext db, ITokenService tokenService, ICookieService cookieService, HttpResponse response) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == login.Username);
    
    if (user is null || !BCrypt.Net.BCrypt.Verify(login.Password, user.Password))
        return Results.Unauthorized();

    var token = tokenService.GenerateToken(user);
    cookieService.SetJwtCookie(response, token, TimeSpan.FromHours(1));

    return Results.Ok("Login realizado com sucesso");
});


app.MapPost("/logout", (HttpResponse response, ICookieService cookieService) =>
{
    cookieService.ClearJwtCookie(response);
    return Results.Ok("Logout realizado com sucesso");
});

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
