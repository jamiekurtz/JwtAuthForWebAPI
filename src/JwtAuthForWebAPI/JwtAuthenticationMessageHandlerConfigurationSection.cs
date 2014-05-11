// JwtAuthenticationMessageHandlerConfigurationSection.cs
// Copyright fiserv 2014.

using System.Configuration;

namespace JwtAuthForWebAPI
{
    public class JwtAuthenticationMessageHandlerConfigurationSection : ConfigurationSection
    {
        public static readonly JwtAuthenticationMessageHandlerConfigurationSection Current =
            (JwtAuthenticationMessageHandlerConfigurationSection) ConfigurationManager.GetSection
                ("jwtAuthenticationMessageHandlerConfiguration");

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
            get { return (string)base["AllowedAudiences"]; }
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
    }
}