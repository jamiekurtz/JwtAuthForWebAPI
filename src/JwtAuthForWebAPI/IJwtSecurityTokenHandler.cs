using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     A JWT security token handler.
    /// </summary>
    public interface IJwtSecurityTokenHandler
    {
        /// <summary>
        ///     Validates the specified token and returns a <see cref="ClaimsPrincipal" /> instance.
        /// </summary>
        /// <param name="securityToken">The token to validate.</param>
        /// <param name="validationParameters">The parameters to apply in the validation.</param>
        ClaimsPrincipal ValidateToken(IJwtSecurityToken securityToken, TokenValidationParameters validationParameters);
    }
}