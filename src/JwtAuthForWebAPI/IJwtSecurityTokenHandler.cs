using System.IdentityModel.Tokens;
using System.Security.Principal;

namespace JwtAuthForWebAPI
{
    public interface IJwtSecurityTokenHandler
    {
        IPrincipal ValidateToken(IJwtSecurityToken securityToken, TokenValidationParameters validationParameters);
    }
}