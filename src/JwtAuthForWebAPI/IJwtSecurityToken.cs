namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     A JWT security token.
    /// </summary>
    public interface IJwtSecurityToken
    {
        System.IdentityModel.Tokens.JwtSecurityToken Inner { get; }
    }
}