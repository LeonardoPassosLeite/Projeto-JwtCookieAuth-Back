namespace JwtCookieAuthApi.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty; // ⚠️ Em produção, use hash!
}
