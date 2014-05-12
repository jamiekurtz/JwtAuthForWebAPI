using System.IdentityModel.Tokens;

namespace JwtAuthForWebAPI
{
    public class JwtSecurityTokenAdapter : IJwtSecurityToken
    {
        private readonly JwtSecurityToken _inner;

        public JwtSecurityTokenAdapter(string tokenString)
        {
            _inner = new JwtSecurityToken(tokenString);
        }

        public string SignatureAlgorithm
        {
            get { return _inner.SignatureAlgorithm; }
        }

        public string RawData
        {
            get { return _inner.RawData; }
        }
    }
}