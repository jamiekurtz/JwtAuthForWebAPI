using System;
using System.Text;
using System.Web.Http;
using JwtAuthForWebAPI.SampleSite.Security;

namespace JwtAuthForWebAPI.SampleSite
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new {id = RouteParameter.Optional}
                );


            var tokenBuilder = new SecurityTokenBuilder();
            var configReader = new ConfigurationReader();

            var jwtHandlerCert = new JwtAuthenticationMessageHandler
            {
                AllowedAudience = configReader.AllowedAudience,
                AllowedAudiences = configReader.AllowedAudiences,
                Issuer = configReader.Issuer,
                SigningToken = tokenBuilder.CreateFromCertificate(configReader.SubjectCertificateName),
                PrincipalTransformer = new SamplePrincipalTransformer()
            };    
        
            var jwtHandlerSharedKey = new JwtAuthenticationMessageHandler
            {
                AllowedAudience = configReader.AllowedAudience,
                Issuer = configReader.Issuer,
                SigningToken = tokenBuilder.CreateFromKey(configReader.SymmetricKey),
                PrincipalTransformer = new SamplePrincipalTransformer(),
                CookieNameToCheckForToken = configReader.CookieNameToCheckForToken
            };

            config.MessageHandlers.Add(jwtHandlerCert);
            config.MessageHandlers.Add(jwtHandlerSharedKey);


            // Uncomment the following line of code to enable query support for actions with an IQueryable or IQueryable<T> return type.
            // To avoid processing unexpected or malicious queries, use the validation settings on QueryableAttribute to validate incoming queries.
            // For more information, visit http://go.microsoft.com/fwlink/?LinkId=279712.
            //config.EnableQuerySupport();

            // To disable tracing in your application, please comment out or remove the following line of code
            // For more information, refer to: http://www.asp.net/web-api
            config.EnableSystemDiagnosticsTracing();
        }
    }
}