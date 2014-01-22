namespace JwtAuthForWebAPI
{
    public class JwtSecurityTokenAdapter : IJwtSecurityToken
    {
        public System.IdentityModel.Tokens.JwtSecurityToken Inner { get; private set; }

        public JwtSecurityTokenAdapter(string tokenString)
        {
            Inner = new System.IdentityModel.Tokens.JwtSecurityToken(tokenString);
        }
    }
}