
namespace JwtCookieAuthApi.Services.IServices
{
    public interface ICookieService
    {
        void SetJwtCookie(HttpResponse response, string token, TimeSpan expiration);
        void ClearJwtCookie(HttpResponse response);
    }
}
