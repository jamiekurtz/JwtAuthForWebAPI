using System;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace JwtAuthForWebAPI
{
    public class JWtAuthenticationMessageHandler : DelegatingHandler
    {
        public const string BearerScheme = "Bearer";

        public JWtAuthenticationMessageHandler()
        {
            AllowedAudience = "http://www.example.com";
            Issuer = "self";
        }

        public SecurityToken SigningToken { get; set; }

        public string AllowedAudience { get; set; }

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
        /// Sets the <see cref="SecurityToken"/> property with an X509 certificate obtained from the local machine using the 
        /// given search criteria. The search criteria must result in exactly one certificate being found.
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
                string msg = string.Format(
                    "Certificate in store '{0}' and location '{1}' and findType '{2}' and findValue '{3}' not found.",
                    certificateStore,
                    certificateStoreLocation,
                    findType,
                    findValue);
                throw new Exception(msg);
            }

            if (certs.Count > 1)
            {
                string msg = string.Format(
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

        public void SetSecurityTokenWithSharedKey(string asciiEncodedKeyString)
        {
            SetSecurityTokenWithSharedKey(asciiEncodedKeyString, Encoding.ASCII);
        }

        public void SetSecurityTokenWithSharedKey(string key, Encoding encoding)
        {
            var bytes = encoding.GetBytes(key);
            SetSecurityTokenWithSharedKey(bytes);
        }

        public void SetSecurityTokenWithSharedKey(byte[] key)
        {
            SigningToken = new BinarySecretSecurityToken(key);
        }
    }
}