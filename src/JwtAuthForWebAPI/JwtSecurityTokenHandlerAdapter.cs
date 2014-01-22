using System.IdentityModel.Tokens;
using System.Security.Principal;

namespace JwtAuthForWebAPI
{
    public class JwtSecurityTokenHandlerAdapter : IJwtSecurityTokenHandler
    {
        private readonly JwtSecurityTokenHandler _securityTokenHandler;

        public JwtSecurityTokenHandlerAdapter()
        {
            _securityTokenHandler = new JwtSecurityTokenHandler();
        }

        public IPrincipal ValidateToken(IJwtSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return _securityTokenHandler.ValidateToken(((JwtSecurityTokenAdapter) securityToken).Inner, validationParameters);
        }
    }
}