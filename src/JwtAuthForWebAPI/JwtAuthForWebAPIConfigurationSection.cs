using System.Configuration;

namespace JwtAuthForWebAPI
{
    internal class JwtAuthForWebApiConfigurationSection : ConfigurationSection
    {
        public static readonly JwtAuthForWebApiConfigurationSection Current =
            (JwtAuthForWebApiConfigurationSection) ConfigurationManager.GetSection
                ("JwtAuthForWebAPI");

        [ConfigurationProperty("EnableAuthenticationMessageHandler", DefaultValue = "false")]
        public bool EnableAuthenticationMessageHandler
        {
            get { return (bool) base["EnableAuthenticationMessageHandler"]; }
            set { base["EnableAuthenticationMessageHandler"] = value; }
        }

        [ConfigurationProperty("AllowedAudience", DefaultValue = "")]
        public string AllowedAudience
        {
            get { return (string) base["AllowedAudience"]; }
            set { base["AllowedAudience"] = value; }
        }

        [ConfigurationProperty("AllowedAudiences", DefaultValue = "")]
        public string AllowedAudiences
        {
            get { return (string) base["AllowedAudiences"]; }
            set { base["AllowedAudiences"] = value; }
        }

        [ConfigurationProperty("Issuer", DefaultValue = "")]
        public string Issuer
        {
            get { return (string) base["Issuer"]; }
            set { base["Issuer"] = value; }
        }

        [ConfigurationProperty("SubjectCertificateName", DefaultValue = "")]
        public string SubjectCertificateName
        {
            get { return (string) base["SubjectCertificateName"]; }
            set { base["SubjectCertificateName"] = value; }
        }

        [ConfigurationProperty("SymmetricKey", DefaultValue = "")]
        public string SymmetricKey
        {
            get { return (string)base["SymmetricKey"]; }
            set { base["SymmetricKey"] = value; }
        }

        [ConfigurationProperty("CookieNameToCheckForToken", DefaultValue = "")]
        public string CookieNameToCheckForToken
        {
            get { return (string)base["CookieNameToCheckForToken"]; }
            set { base["CookieNameToCheckForToken"] = value; }
        }
    }
}