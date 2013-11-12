using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using log4net;

namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     Token handler used to validate JSON Web Tokens (JWTs) that are included in the Authorization header of
    ///     an incoming HTTP request. The authorization scheme must be set to Bearer.
    ///     To use, add an instance of this handler to the GlobalConfiguration.Configuration.MessageHandlers collection.
    /// </summary>
    public class JwtAuthenticationMessageHandler : DelegatingHandler
    {
        /// <summary>
        ///     String representation of the Bearer scheme, used for JWTs.
        /// </summary>
        public const string BearerScheme = "Bearer";

        private readonly ILog _logger = LogManager.GetLogger("JwtAuthForWebAPI");

        public JwtAuthenticationMessageHandler()
        {
            AllowedAudience = "http://www.example.com";
            Issuer = "self";
        }

        /// <summary>
        ///     Gets or sets the token to use to verify the signature of incoming JWTs.
        /// </summary>
        public SecurityToken SigningToken { get; set; }

        /// <summary>
        ///     Gets or sets the audience (usually a URL, but really just an arbitrary string) that
        ///     will be used during validation of incoming JWTs. This value must match the AppliesToAddress
        ///     value on the token. Default value is "http://www.example.com".
        /// </summary>
        public string AllowedAudience { get; set; }
        
        /// <summary>
        ///     Gets or sets a list of audience values (usually URLs, but really just an arbitrary string) that
        ///     will be used during validation of incoming JWTs. At least one value in this list must match 
        ///     the AppliesToAddress value on the token. 
        /// </summary>
        public IEnumerable<string> AllowedAudiences { get; set; }

        /// <summary>
        ///     Gets or sets the issuer (usually a URL, but really just an arbitrary string) that
        ///     will be used during validation of incoming JWTs. This value must match the TokenIssuerName
        ///     value on the token. Default value is "self".
        /// </summary>
        public string Issuer { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var authHeader = request.Headers.Authorization;
            if (authHeader == null)
            {
                _logger.Info("Missing authorization header");
                return base.SendAsync(request, cancellationToken);
            }

            if (authHeader.Scheme != BearerScheme)
            {
                _logger.InfoFormat(
                    "Authorization header scheme is {0}; needs to {1} to be handled as a JWT.",
                    authHeader.Scheme,
                    BearerScheme);
                return base.SendAsync(request, cancellationToken);
            }

            var parameters = new TokenValidationParameters
            {
                AllowedAudience = AllowedAudience,
                SigningToken = SigningToken,
                ValidIssuer = Issuer,
                AllowedAudiences = AllowedAudiences
            };

            var tokenString = authHeader.Parameter;
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(tokenString);

            try
            {
                var principal = tokenHandler.ValidateToken(token, parameters);

                Thread.CurrentPrincipal = principal;
                _logger.DebugFormat("Thread principal set with identity '{0}'", principal.Identity.Name);

                if (HttpContext.Current != null)
                {
                    HttpContext.Current.User = principal;
                }
            }
            catch (SecurityTokenValidationException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);
                throw;
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}