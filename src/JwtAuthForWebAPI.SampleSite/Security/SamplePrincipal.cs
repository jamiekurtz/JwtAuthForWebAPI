using System.Collections.Specialized;
using System.Security.Principal;

namespace JwtAuthForWebAPI.SampleSite.Security
{
    public class SamplePrincipal : IPrincipal
    {
        private readonly StringCollection _roles = new StringCollection();

        public SamplePrincipal(IIdentity identity, string[] roles)
        {
            Identity = identity;
            _roles.AddRange(roles);
        }

        public bool IsInRole(string role)
        {
            return _roles.Contains(role);
        }

        public IIdentity Identity { get; private set; }
    }
}