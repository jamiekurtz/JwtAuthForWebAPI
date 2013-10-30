using System;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace JwtAuthForWebAPI
{
    /// <summary>
    /// Token handler used to validate JSON Web Tokens (JWTs) that are included in the Authorization header of
    /// an incoming HTTP request. The authorization scheme must be set to Bearer.
    /// 
    /// To use, add an instance of this handler to the GlobalConfiguration.Configuration.MessageHandlers collection. 
    /// </summary>
    public class JWtAuthenticationMessageHandler : DelegatingHandler
    {
        public const string BearerScheme = "Bearer";

        public JWtAuthenticationMessageHandler()
        {
            AllowedAudience = "http://www.example.com";
            Issuer = "self";
        }

        /// <summary>
        /// Gets or sets the token to use to verify the signature of incoming JWTs.
        /// </summary>
        public SecurityToken SigningToken { get; set; }

        /// <summary>
        /// Gets or sets the audience (usually a URL, but really just an arbitrary string) that 
        /// will be used during validation of incoming JWTs. This value must match the AppliesToAddress 
        /// value on the token. Default value is "http://www.example.com".
        /// </summary>
        public string AllowedAudience { get; set; }

        /// <summary>
        /// Gets or sets the issuer (usually a URL, but really just an arbitrary string) that 
        /// will be used during validation of incoming JWTs. This value must match the TokenIssuerName 
        /// value on the token. Default value is "self".
        /// </summary>
        public string Issuer { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var authHeader = request.Headers.Authorization;
            if (authHeader == null)
            {
                return base.SendAsync(request, cancellationToken);
            }

            if (authHeader.Scheme != BearerScheme)
            {
                return base.SendAsync(request, cancellationToken);
            }

            var parameters = new TokenValidationParameters
            {
                AllowedAudience = AllowedAudience,
                SigningToken = SigningToken,
                ValidIssuer = Issuer
            };

            var tokenString = authHeader.Parameter;
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(tokenString);

            var principal = tokenHandler.ValidateToken(token, parameters);

            Thread.CurrentPrincipal = principal;

            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }

            return base.SendAsync(request, cancellationToken);
        }

        /// <summary>
        ///     Sets the <see cref="SecurityToken" /> property with an X509 certificate obtained from the local machine using the
        ///     given search criteria. The search criteria must result in exactly one certificate being found.
        /// </summary>
        public void SetSecurityTokenWithCertificate(
            X509FindType findType,
            string findValue,
            StoreName certificateStore = StoreName.My,
            StoreLocation certificateStoreLocation = StoreLocation.LocalMachine)
        {
            var store = new X509Store(certificateStore, certificateStoreLocation);
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates.Find(findType, findValue, true);

            if (certs.Count == 0)
            {
                var msg = string.Format(
                    "Certificate in store '{0}' and location '{1}' and findType '{2}' and findValue '{3}' not found.",
                    certificateStore,
                    certificateStoreLocation,
                    findType,
                    findValue);
                throw new Exception(msg);
            }

            if (certs.Count > 1)
            {
                var msg = string.Format(
                    "More than one certificate with store '{0}' and location '{1}' and findType '{2}' and findValue '{3}' found.",
                    certificateStore,
                    certificateStoreLocation,
                    findType,
                    findValue);
                throw new Exception(msg);
            }

            var certificate = new X509Certificate2(certs[0].GetPublicKey());
            SigningToken = new X509SecurityToken(certificate);
        }

        /// <summary>
        /// Sets the <see cref="SecurityToken" /> property with an shared-key token created from the 
        /// given base64 encoded string.
        /// </summary>
        public void SetSecurityTokenWithSharedKey(string base64Key)
        {
            SetSecurityTokenWithSharedKey(Convert.FromBase64String(base64Key));
        }

        /// <summary>
        /// Sets the <see cref="SecurityToken" /> property with an shared-key token created from the 
        /// given byte array key.
        /// </summary>
        public void SetSecurityTokenWithSharedKey(byte[] key)
        {
            SigningToken = new BinarySecretSecurityToken(key);
        }
    }
}