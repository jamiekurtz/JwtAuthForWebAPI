using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using NUnit.Framework;

namespace JwtAuthForWebAPI.SampleClient
{
    [TestFixture]
    public class SmokeTests
    {
        public readonly Uri ApiUrl = new Uri("http://localhost:20250/");
        public const string CertificateSubjectName = "CN=JwtAuthForWebAPI Example";

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
            AddAuthHeader(client);

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

        private void AddAuthHeader(HttpClient client)
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
                AppliesToAddress = "http://www.example.com",
                SigningCredentials = new X509SigningCredentials(signingCert)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenString);
        }
    }
}