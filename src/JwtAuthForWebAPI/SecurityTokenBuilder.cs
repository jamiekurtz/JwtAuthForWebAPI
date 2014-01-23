using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;

namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     Helper class to create security tokens from various inputs (e.g. shared-key, certificate information).
    /// </summary>
    public class SecurityTokenBuilder
    {
        /// <summary>
        ///     Creates a new <see cref="SecurityToken" /> using a shared-key token created from the
        ///     given byte array key.
        /// </summary>
        public SecurityToken CreateFromKey(byte[] key)
        {
            return new BinarySecretSecurityToken(key);
        }

        /// <summary>
        ///     Creates a new <see cref="SecurityToken" /> using an shared-key token created from the
        ///     given base64 encoded string.
        /// </summary>
        public SecurityToken CreateFromKey(string base64Key)
        {
            return CreateFromKey(Convert.FromBase64String(base64Key));
        }

        public SecurityToken CreateFromCertificate(X509Certificate2 cert)
        {
            return new X509SecurityToken(cert);
        }

        /// <summary>
        ///     Creates a <see cref="SecurityToken" /> using an X509 certificate obtained from the local machine using the
        ///     given subject name, store, and store location. The search criteria must result in exactly one certificate being
        ///     found.
        /// </summary>
        /// <param name="subjectName">The subjectName of the certificate to find. Should be prefixed with form "CN=".</param>
        /// <param name="certificateStore">The certificate store to use for finding the certificate: defaults to My.</param>
        /// <param name="certificateStoreLocation">The store location to use to find the certificate; defaults to LocalMachine.</param>
        public SecurityToken CreateFromCertificate(
            string subjectName,
            StoreName certificateStore = StoreName.My,
            StoreLocation certificateStoreLocation = StoreLocation.LocalMachine)
        {
            var store = new X509Store(certificateStore, certificateStoreLocation);
            store.Open(OpenFlags.ReadOnly);

            try
            {
                var certs = store.Certificates
                    .OfType<X509Certificate2>()
                    .Where(x => x.SubjectName.Name != null 
                        && x.SubjectName.Name.Equals(subjectName, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (certs.Count == 0)
                {
                    var msg = string.Format(
                        "Certificate in store '{0}' and location '{1}' and SubjectName '{2}' not found.",
                        certificateStore,
                        certificateStoreLocation,
                        subjectName);
                    throw new Exception(msg);
                }

                if (certs.Count > 1)
                {
                    var msg = string.Format(
                        "More than one certificate with store '{0}' and location '{1}' and SubjectName '{2}' found.",
                        certificateStore,
                        certificateStoreLocation,
                        subjectName);
                    throw new Exception(msg);
                }

                return CreateFromCertificate(certs[0]);
            }
            finally
            {
                store.Certificates.OfType<X509Certificate2>().ToList().ForEach(x => x.Reset());
                store.Close();
            }
        }

        /// <summary>
        ///     Creates a new <see cref="SecurityToken" /> using an X509 certificate obtained from the local machine using the
        ///     given search criteria. The search criteria must result in exactly one certificate being found.
        ///     Note that to create a token from a certificate's subject name you should use the other overload for this method
        ///     (that
        ///     specifically takes a subject name).
        /// </summary>
        /// <param name="findValue">The string to use to find the certificate according to the <see cref="findType" /> parameter.</param>
        /// <param name="findType">The type of search to use for finding the certificate.</param>
        /// <param name="certificateStore">The certificate store to use for finding the certificate: defaults to My.</param>
        /// <param name="certificateStoreLocation">The store location to use to find the certificate; defaults to LocalMachine.</param>
        public SecurityToken CreateFromCertificate(
            string findValue,
            X509FindType findType,
            StoreName certificateStore = StoreName.My,
            StoreLocation certificateStoreLocation = StoreLocation.LocalMachine)
        {
            var store = new X509Store(certificateStore, certificateStoreLocation);
            store.Open(OpenFlags.ReadOnly);

            try
            {
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

                return CreateFromCertificate(certs[0]);
            }
            finally
            {
                store.Certificates.OfType<X509Certificate2>().ToList().ForEach(x => x.Reset());
                store.Close();
            }
        }
    }
}