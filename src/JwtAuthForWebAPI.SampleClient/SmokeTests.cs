using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using FluentAssertions;
using NUnit.Framework;

namespace JwtAuthForWebAPI.SampleClient
{
    [TestFixture]
    public class SmokeTests
    {
        public readonly Uri ApiUrl = new Uri("http://localhost:20250/");
        public const string CertificateSubjectName = "CN=JwtAuthForWebAPI Example";
        public const string SymmetricKey = "YQBiAGMAZABlAGYAZwBoAGkAagBrAGwAbQBuAG8AcABxAHIAcwB0AHUAdgB3AHgAeQB6ADAAMQAyADMANAA1AA==";

        [Test]
        public void call_without_token_to_protected_resource_should_fail_with_401()
        {
            var client = new HttpClient {BaseAddress = ApiUrl};

            var response = client.GetAsync("api/values").Result;

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Test]
        public void call_with_token_to_protected_resource_should_succeed_with_200_and_caller_name()
        {
            var client = new HttpClient {BaseAddress = ApiUrl};
            AddAuthHeaderWithCert(client);

            var response = client.GetAsync("api/values").Result;

            response.StatusCode.Should().Be(HttpStatusCode.OK);

            var responseMessage = response.Content.ReadAsStringAsync().Result;
            responseMessage.Should().Contain("bsmith");
        }

        [Test]
        public void call_with_sharedKey_token_to_protected_resource_should_succeed_with_200_and_caller_name()
        {
            var client = new HttpClient {BaseAddress = ApiUrl};
            AddAuthHeaderWithSharedKey(client);

            var response = client.GetAsync("api/values").Result;

            response.StatusCode.Should().Be(HttpStatusCode.OK);

            var responseMessage = response.Content.ReadAsStringAsync().Result;
            responseMessage.Should().Contain("bsmith");
        }

        [Test]
        public void call_without_token_to_allowanonymous_resource_should_succeed_with_200()
        {
            var client = new HttpClient {BaseAddress = ApiUrl};

            var response = client.PostAsync("api/values", new StringContent("some new value")).Result;

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Test]
        public void call_with_token_with_wrong_role_should_fail_with_401()
        {
            var client = new HttpClient {BaseAddress = ApiUrl};

            var response = client.DeleteAsync("api/values/123").Result;

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
        
        [Test]
        public void call_with_token_with_different_audience_should_still_succeed()
        {
            var client = new HttpClient { BaseAddress = ApiUrl };
            AddAuthHeaderWithCert(client, "http://www.anotherexample.com");

            var response = client.GetAsync("api/values").Result;

            response.StatusCode.Should().Be(HttpStatusCode.OK);

            var responseMessage = response.Content.ReadAsStringAsync().Result;
            responseMessage.Should().Contain("bsmith");
        }

        private void AddAuthHeaderWithCert(HttpClient client)
        {
            AddAuthHeaderWithCert(client, "http://www.example.com");
        }

        private void AddAuthHeaderWithSharedKey(HttpClient client)
        {
            AddAuthHeaderWithSharedKey(client, "http://www.example.com");
        }

        private void AddAuthHeaderWithCert(HttpClient client, string audience)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var signingCert = store.Certificates
                .Cast<X509Certificate2>()
                .FirstOrDefault(certificate => certificate.Subject == CertificateSubjectName);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "bsmith"), 
                    new Claim(ClaimTypes.GivenName, "Bob"),
                    new Claim(ClaimTypes.Surname, "Smith"),
                    new Claim(ClaimTypes.Role, "Customer Service")
                }),
                TokenIssuerName = "corp",
                AppliesToAddress = audience,
                SigningCredentials = new X509SigningCredentials(signingCert)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenString);
        }

        private void AddAuthHeaderWithSharedKey(HttpClient client, string audience)
        {
            var key = Convert.FromBase64String(SymmetricKey);
            var credentials = new SigningCredentials(
                new InMemorySymmetricSecurityKey(key),
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "bsmith"), 
                    new Claim(ClaimTypes.GivenName, "Bob"),
                    new Claim(ClaimTypes.Surname, "Smith"),
                    new Claim(ClaimTypes.Role, "Customer Service")
                }),
                TokenIssuerName = "corp",
                AppliesToAddress = audience,
                SigningCredentials = credentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenString);
        }
    }
}