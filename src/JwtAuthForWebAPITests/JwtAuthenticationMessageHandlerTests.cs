using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
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

            protected override Task<HttpResponseMessage> BaseSendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage());
            }
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
    }
}