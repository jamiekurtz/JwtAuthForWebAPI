using System.Security.Claims;
using System.Security.Principal;

namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     Provides functionality to transform the standard <see cref="ClaimsPrincipal" /> generated from the
    ///     <see cref="IJwtSecurityTokenHandler" /> into a custom one.
    /// </summary>
    public interface IPrincipalTransformer
    {
        /// <summary>
        ///     Transforms a <see cref="ClaimsPrincipal" /> into a custom one.
        /// </summary>
        /// <param name="principal">Principal to transform.</param>
        IPrincipal Transform(ClaimsPrincipal principal);
    }
}