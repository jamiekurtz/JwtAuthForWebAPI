namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     Used to read configuration values from web.config specific to this library.
    /// </summary>
    public class ConfigurationReader
    {
        /// <summary>
        ///     Gets a boolean representing the configured EnableAuthenticationMessageHandler vaue
        /// </summary>
        public bool EnableAuthenticationMessageHandler
        {
            get { return JwtAuthForWebApiConfigurationSection.Current.EnableAuthenticationMessageHandler; }
        }

        /// <summary>
        ///     Gets a string representing the configured AllowedAudience value
        /// </summary>
        public string AllowedAudience
        {
            get { return JwtAuthForWebApiConfigurationSection.Current.AllowedAudience; }
        }

        /// <summary>
        ///     Gets a string arrary representing the configured AllowedAudiences value
        /// </summary>
        public string[] AllowedAudiences
        {
            get
            {
                return string.IsNullOrWhiteSpace(JwtAuthForWebApiConfigurationSection.Current.AllowedAudiences)
                    ? new string[0]
                    : JwtAuthForWebApiConfigurationSection.Current.AllowedAudiences.Split(new[] {';', ','});
            }
        }

        /// <summary>
        ///     Gets a string representing the configured Issuer value
        /// </summary>
        public string Issuer
        {
            get { return JwtAuthForWebApiConfigurationSection.Current.Issuer; }
        }

        /// <summary>
        ///     Gets a string representing the configured SubjectCertificateName value
        /// </summary>
        public string SubjectCertificateName
        {
            get { return JwtAuthForWebApiConfigurationSection.Current.SubjectCertificateName; }
        }

        /// <summary>
        ///     Gets a string representing the configured SymmetricKey value
        /// </summary>
        public string SymmetricKey
        {
            get { return JwtAuthForWebApiConfigurationSection.Current.SymmetricKey; }
        }
    }
}