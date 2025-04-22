using JwtCookieAuthApi.Models;

namespace JwtCookieAuthApi.Services.IServices
{
    public interface ITokenService
    {
        string GenerateToken(User user);
    }
}