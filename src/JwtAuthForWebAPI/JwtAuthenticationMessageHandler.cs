using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.ServiceModel.Security.Tokens;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     Token handler used to validate JSON Web Tokens (JWTs) that are included in the Authorization header of
    ///     an incoming HTTP request. The authorization scheme must be set to Bearer.
    ///     To use, add an instance of this handler to the GlobalConfiguration.Configuration.MessageHandlers collection.
    /// </summary>
    public class JwtAuthenticationMessageHandler : DelegatingHandler
    {
        private readonly ILogger _logger = new DefaultLogger();

        /// <summary>
        ///     String representation of the Bearer scheme, used for JWTs.
        /// </summary>
        public const string BearerScheme = "Bearer";

        public JwtAuthenticationMessageHandler(ILogger logger) : base()
        {
            _logger = logger;
        }

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

        /// <summary>
        ///     Gets or sets the <see cref="IPrincipalTransformer" /> that converts a principal into a custom
        ///     principal. May be null.
        /// </summary>
        public IPrincipalTransformer PrincipalTransformer { get; set; }

        /// <summary>
        ///     If set (i.e. not empty and not null), the handler will also look in the request's cookie collection for
        ///     a cookie by the given name and that contains a valid JWT.
        /// </summary>
        public string CookieNameToCheckForToken { get; set; }

        protected virtual Task<HttpResponseMessage> BaseSendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return base.SendAsync(request, cancellationToken);
        }

        protected virtual string GetTokenStringFromHeader(HttpRequestMessage request)
        {
            var authHeader = request.Headers.Authorization;
            if (authHeader == null) return null;

            if (authHeader.Scheme != BearerScheme)
            {
                _logger.DebugFormat(
                    "Authorization header scheme is {0}; needs to be {1} to be handled as a JWT.",
                    authHeader.Scheme,
                    BearerScheme);
            }
            else
            {
                return authHeader.Parameter;
            }

            return null;
        }

        protected virtual string GetTokenStringFromCookie(string cookieName)
        {
            if (string.IsNullOrEmpty(cookieName)) return null;

            var cookie = HttpContext.Current.Request.Cookies[cookieName];
            if (cookie == null)
            {
                _logger.DebugFormat("Cookie by name {0} not found.", cookieName);
                return null;
            }

            return cookie.Value;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var tokenStringFromHeader = GetTokenStringFromHeader(request);
            var tokenStringFromCookie = GetTokenStringFromCookie(CookieNameToCheckForToken);
            var tokenString = tokenStringFromHeader ?? tokenStringFromCookie;

            if (!string.IsNullOrEmpty(tokenStringFromHeader) && !string.IsNullOrEmpty(tokenStringFromCookie))
            {
                _logger.DebugFormat(
                    "Both the Authorization header and {0} cookie contained tokens; header token was used",
                    CookieNameToCheckForToken);
            }

            if (string.IsNullOrEmpty(tokenString))
            {
                _logger.DebugFormat("Token not found in authorization header or request cookie");
                return BaseSendAsync(request, cancellationToken);
            }

            IJwtSecurityToken token;
            try
            {
                token = CreateToken(tokenString);
            }
            catch (Exception ex)
            {
                _logger.WarnFormat("Error converting token string to JWT: {0}", ex);
                return BaseSendAsync(request, cancellationToken);
            }

            if (SigningToken != null && token.SignatureAlgorithm != null)
            {
                if (token.SignatureAlgorithm.StartsWith("RS") && !(SigningToken is X509SecurityToken))
                {
                    _logger.DebugFormat("Incoming token signature is X509, but token handler's signing token is not.");
                    return BaseSendAsync(request, cancellationToken);
                }

                if (token.SignatureAlgorithm.StartsWith("HS") && !(SigningToken is BinarySecretSecurityToken))
                {
                    _logger.DebugFormat("Incoming token signature is SHA, but token handler's signing token is not.");
                    return BaseSendAsync(request, cancellationToken);
                }
            }

            var parameters = new TokenValidationParameters
            {
                ValidAudience = AllowedAudience,
                IssuerSigningToken = SigningToken,
                ValidIssuer = Issuer,
                ValidAudiences = AllowedAudiences
            };

            try
            {
                var tokenHandler = CreateTokenHandler();
                IPrincipal principal = tokenHandler.ValidateToken(token, parameters);

                if (PrincipalTransformer != null)
                {
                    principal = PrincipalTransformer.Transform((ClaimsPrincipal) principal);
                    CheckPrincipal(principal, PrincipalTransformer.GetType());
                }

                Thread.CurrentPrincipal = principal;
                _logger.DebugFormat("Thread principal set with identity '{0}'", principal.Identity.Name);

                if (HttpContext.Current != null)
                {
                    HttpContext.Current.User = principal;
                }
            }
            catch (SecurityTokenExpiredException e)
            {
                _logger.ErrorFormat("Security token expired: {0}", e);

                var response = new HttpResponseMessage((HttpStatusCode) 440)
                {
                    Content = new StringContent("Security token expired exception")
                };

                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }
            catch (SecurityTokenSignatureKeyNotFoundException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Untrusted signing cert")
                };

                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }
            catch (SecurityTokenInvalidAudienceException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Invalid token audience")
                };

                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }
            catch (SecurityTokenValidationException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Invalid token")
                };

                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }
            catch (SignatureVerificationFailedException e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);

                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Invalid token signature")
                };

                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }
            catch (Exception e)
            {
                _logger.ErrorFormat("Error during JWT validation: {0}", e);
                throw;
            }

            return BaseSendAsync(request, cancellationToken);
        }

        protected virtual void CheckPrincipal(IPrincipal principal, Type transformerType)
        {
            if (principal == null)
            {
                throw new Exception("The principal object returned by the PrincipalTransformer (of type " +
                                    transformerType.FullName + ") cannot be null.");
            }

            if (principal.Identity == null)
            {
                throw new Exception("The principal object returned by the PrincipalTransformer (of type " +
                                    transformerType.FullName + ") must include a non-null Identity.");
            }
        }

        protected virtual IJwtSecurityToken CreateToken(string tokenString)
        {
            return new JwtSecurityTokenAdapter(tokenString);
        }

        protected virtual IJwtSecurityTokenHandler CreateTokenHandler()
        {
            return new JwtSecurityTokenHandlerAdapter();
        }
    }
}