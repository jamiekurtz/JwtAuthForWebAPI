namespace JwtAuthForWebAPI
{
    /// <summary>
    ///     A JWT security token.
    /// </summary>
    public interface IJwtSecurityToken
    {
        string SignatureAlgorithm { get; }
        string RawData { get; }
    }
}