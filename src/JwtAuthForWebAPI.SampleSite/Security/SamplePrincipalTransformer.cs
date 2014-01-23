using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace JwtAuthForWebAPI.SampleSite.Security
{
    public class SamplePrincipalTransformer : IPrincipalTransformer
    {
        public IPrincipal Transform(ClaimsPrincipal principal)
        {
            var roles = principal
                .FindAll(ClaimTypes.Role)
                .Select(x => x.Value)
                .ToArray();

            return new SamplePrincipal(principal.Identity, roles);
        }
    }
}