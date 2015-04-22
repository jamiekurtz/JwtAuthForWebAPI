using System;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using JwtAuthForWebAPI;
using Moq;
using NUnit.Framework;

namespace JwtAuthForWebAPITests
{
    [TestFixture]
    public class JwtAuthenticationMessageHandlerTests
    {
        [SetUp]
        public void SetUp()
        {
            _securityTokenMock = new Mock<IJwtSecurityToken>();
            _securityTokenHandlerMock = new Mock<IJwtSecurityTokenHandler>();
            _principalTransformerMock = new Mock<IPrincipalTransformer>();

            _textMessageWriter = new TextMessageWriter();

            _authenticationMessageHandler = new JwtAuthenticationMessageHandlerTestDouble(_securityTokenMock.Object,
                _securityTokenHandlerMock.Object);

            Thread.CurrentPrincipal = null;
            HttpContext.Current = new HttpContext(new HttpRequest("foo", "http://www.foo.com", null),
                new HttpResponse(_textMessageWriter));
        }

        [TearDown]
        public void TearDown()
        {
            _textMessageWriter.Dispose();
        }

        private TextMessageWriter _textMessageWriter;

        private Mock<IJwtSecurityToken> _securityTokenMock;

        private Mock<IJwtSecurityTokenHandler> _securityTokenHandlerMock;

        private Mock<IPrincipalTransformer> _principalTransformerMock;

        private JwtAuthenticationMessageHandlerTestDouble _authenticationMessageHandler;

        private class JwtAuthenticationMessageHandlerTestDouble : JwtAuthenticationMessageHandler
        {
            private readonly IJwtSecurityTokenHandler _handler;
            private readonly IJwtSecurityToken _token;

            public JwtAuthenticationMessageHandlerTestDouble(IJwtSecurityToken token, IJwtSecurityTokenHandler handler)
            {
                _token = token;
                _handler = handler;
            }

            public new Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                return base.SendAsync(request, cancellationToken);
            }

            protected override IJwtSecurityToken CreateToken(string tokenString)
            {
                return _token;
            }

            protected override IJwtSecurityTokenHandler CreateTokenHandler()
            {
                return _handler;
            }

            protected override string GetTokenStringFromHeader(HttpRequestMessage request)
            {
                return "not null";
            }

            protected override Task<HttpResponseMessage> BaseSendAsync(HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage());
            }

            public void CheckPrincipalDouble(IPrincipal principal, Type transformerType)
            {
                CheckPrincipal(principal, transformerType);
            }
        }

        public class TestPrincipal : IPrincipal
        {
            private readonly StringCollection _roles = new StringCollection();

            public TestPrincipal(IIdentity identity, string[] roles)
            {
                Identity = identity;
                _roles.AddRange(roles);
            }

            public bool IsInRole(string role)
            {
                return _roles.Contains(role);
            }

            public IIdentity Identity { get; private set; }
        }

        [Test]
        public async Task SendAsync_sets_principal()
        {
            var requestMessage = new HttpRequestMessage();
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer");

            var principal = new ClaimsPrincipal(new ClaimsIdentity());

            _securityTokenHandlerMock.Setup(
                x => x.ValidateToken(_securityTokenMock.Object, It.IsAny<TokenValidationParameters>()))
                .Returns(principal);

            await _authenticationMessageHandler.SendAsync(requestMessage, CancellationToken.None);

            Assert.AreSame(principal, Thread.CurrentPrincipal, "Incorrect CurrentPrincipal");
            Assert.AreSame(principal, HttpContext.Current.User, "Incorrect user in context");
        }

        [Test]
        public async Task SendAsync_sets_transformed_principal()
        {
            var requestMessage = new HttpRequestMessage();
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer");

            var principal = new ClaimsPrincipal(new ClaimsIdentity());
            var transformedPrincipal = new GenericPrincipal(new ClaimsIdentity(), new[] {"user"});

            _securityTokenHandlerMock.Setup(
                x => x.ValidateToken(_securityTokenMock.Object, It.IsAny<TokenValidationParameters>()))
                .Returns(principal);
            _principalTransformerMock.Setup(x => x.Transform(principal)).Returns(transformedPrincipal);

            _authenticationMessageHandler.PrincipalTransformer = _principalTransformerMock.Object;

            await _authenticationMessageHandler.SendAsync(requestMessage, CancellationToken.None);

            Assert.AreSame(transformedPrincipal, Thread.CurrentPrincipal, "Incorrect CurrentPrincipal");
            Assert.AreSame(transformedPrincipal, HttpContext.Current.User, "Incorrect user in context");
        }

        [Test]
        public void CheckPrincipal_throws_on_null_principal()
        {
            Assert.Throws<Exception>(() => _authenticationMessageHandler.CheckPrincipalDouble(null, this.GetType()));
        }

        [Test]
        public void CheckPrincipal_throws_on_null_principal_identity()
        {
            var principal = new TestPrincipal(null, new[] {"user"});
            Assert.Throws<Exception>(() => _authenticationMessageHandler.CheckPrincipalDouble(principal, GetType()));
        }
    }
}