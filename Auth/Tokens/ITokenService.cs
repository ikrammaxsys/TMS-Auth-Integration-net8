using System.Security.Claims;

namespace AuthACL.CentralAuth.Tokens;

/// <summary>
/// Validates JWT access tokens issued by the standalone auth service (same signing key / issuer / audience as configured).
/// </summary>
public interface ITokenService
{
    (ClaimsPrincipal? principal, string? error) ValidateToken(string token);

    /// <summary>
    /// Validates the access token and distinguishes expiry from other failures (bad signature, wrong issuer, etc.).
    /// </summary>
    (ClaimsPrincipal? principal, AuthTokenValidationKind kind) ValidateTokenWithKind(string token);
}
