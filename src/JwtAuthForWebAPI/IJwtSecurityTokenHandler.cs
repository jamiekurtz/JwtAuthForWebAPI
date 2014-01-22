using System.IdentityModel.Tokens;
using System.Security.Principal;

namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     A JWT security token handler.
    /// </summary>
    public interface IJwtSecurityTokenHandler
    {
        /// <summary>
        ///     Validates the specified token and returns an <see cref="IPrincipal" /> instance.
        /// </summary>
        /// <param name="securityToken">The token to validate.</param>
        /// <param name="validationParameters">The parameters to apply in the validation.</param>
        IPrincipal ValidateToken(IJwtSecurityToken securityToken, TokenValidationParameters validationParameters);
    }
}