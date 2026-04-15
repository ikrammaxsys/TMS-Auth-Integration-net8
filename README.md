# AuthACL.CentralAuth

Central authentication integration kit providing JWT validation, token refresh, and browser route protection for ASP.NET Core 8+ applications.

## Features

✅ **JWT Validation** - RS256 signature validation with zero clock skew  
✅ **Automatic Token Refresh** - Middleware automatically refreshes expired tokens  
✅ **Browser Route Protection** - Enforces token validation on MVC routes  
✅ **Session Management** - Integrates with ASP.NET Core session for subsystem state  
✅ **Flexible Configuration** - Supports multiple auth service response formats  
✅ **Production-Ready** - Includes logging, error handling, and security best practices

## Installation

```bash
dotnet add package AuthACL.CentralAuth
```

## Quick Start

### 1. Install Package

```bash
dotnet add package AuthACL.CentralAuth
```

### 2. Configure Program.cs

```csharp
using AuthACL.CentralAuth.Jwt;
using AuthACL.CentralAuth.AccessValidation;

var builder = WebApplication.CreateBuilder(args);

// Register authentication services
builder.Services.AddAuthServices(builder.Configuration, builder.Environment);
builder.Services.AddHttpClient();
builder.Services.AddScoped<IAuthTokenRefreshService, AuthTokenRefreshService>();
builder.Services.AddSession();

var app = builder.Build();

// Register middleware (ORDER MATTERS!)
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.UseAccessTokenValidation();  // Add this after UseAuthorization

app.MapControllers();
app.Run();
```

### 3. Configure appsettings.json

```json
{
  "Jwt": {
    "RsaKeyPath": "keys/public.pem",
    "Issuer": "authapi",
    "Audience": "authapi-client"
  },
  "Auth": {
    "BaseUrl": "https://your-auth-service.com",
    "VerifyTokenUrl": "/api/auth/verify-token",
    "ExchangeAuthCodeUrl": "/api/auth/exchange-auth-code",
    "RefreshTokenApiUrl": "/api/auth/refresh-token",
    "LogoutApiUrl": "/api/auth/logout",
    "AccessTokenStorageKey": "authacl_access_token",
    "RefreshTokenStorageKey": "authacl_refresh_token"
  },
  "Vasp": {
    "BaseUrl": "https://your-portal.com"
  }
}
```

### 4. Add RSA Public Key

Place your RSA public key PEM file at `keys/public.pem` (or path specified in `Jwt:RsaKeyPath`).

## What's Included

This package contains **core authentication logic only**:

- JWT validation components (`ITokenService`, `TokenService`, `AuthTokenValidationKind`)
- RSA key loading (`RsaKeyLoader`)
- Service registration (`AddAuthServices`)
- Browser route middleware (`AccessTokenValidationMiddleware`, `UseAccessTokenValidation`)
- Token refresh service (`IAuthTokenRefreshService`, `AuthTokenRefreshService`)
- Authentication models (`AclTokenRequest`, `UserDetail`)

## What You Need to Add

You'll need to copy **4-7 customizable files** for subsystem-specific functionality:

**Required (4 files)**:
- `ACLCheckingController.cs` - Auth gate controller (customize user lookup)
- `Index.cshtml` - Token verification view (customize branding)
- `LogoutPage.cshtml` - Logout view (customize branding)
- `SessionExpired.cshtml` - Session expired view (customize branding)

**Optional (3 files)**:
- `AclProtectedWebController.cs` - Base controller pattern
- `HomeController.cs` - SessionExpired action
- `IndexController.cs` - Default route example

📥 **Download customizable files**: [GitHub Repository](https://github.com/your-org/central-auth-integration-kit) (update with your actual repo URL)

## Usage Examples

### Validate JWT Token

```csharp
public class MyController : Controller
{
    private readonly ITokenService _tokenService;
    
    public MyController(ITokenService tokenService)
    {
        _tokenService = tokenService;
    }
    
    public IActionResult ValidateToken(string token)
    {
        var (principal, kind) = _tokenService.ValidateTokenWithKind(token);
        
        if (kind == AuthTokenValidationKind.Valid)
        {
            var userId = principal.FindFirst("sub")?.Value;
            return Ok(new { userId });
        }
        
        return Unauthorized(new { error = kind.ToString() });
    }
}
```

### Refresh Expired Token

```csharp
public class TokenController : Controller
{
    private readonly IAuthTokenRefreshService _refreshService;
    
    public TokenController(IAuthTokenRefreshService refreshService)
    {
        _refreshService = refreshService;
    }
    
    public async Task<IActionResult> RefreshToken(string refreshToken)
    {
        var result = await _refreshService.TryRefreshAsync(refreshToken);
        
        if (result != null)
        {
            return Ok(new 
            { 
                accessToken = result.AccessToken,
                refreshToken = result.RefreshToken 
            });
        }
        
        return Unauthorized();
    }
}
```

### Customize Middleware Excluded Paths

The middleware automatically skips token validation for:
- `/api` routes (API uses Bearer header separately)
- `/` root path
- `/ACLChecking` auth gate
- `/Home/SessionExpired` session expired page

To customize, create your own middleware based on `AccessTokenValidationMiddleware`.

## Configuration Reference

### Required Configuration

| Key | Description |
|-----|-------------|
| `Jwt:RsaKeyPath` | Path to RSA public key PEM file |
| `Jwt:Issuer` | Expected JWT issuer (must match auth service) |
| `Jwt:Audience` | Expected JWT audience (must match auth service) |
| `Auth:BaseUrl` | Central auth service base URL |
| `Auth:VerifyTokenUrl` | Token verification endpoint path |
| `Auth:ExchangeAuthCodeUrl` | Auth-code exchange endpoint path |
| `Auth:RefreshTokenApiUrl` | Token refresh endpoint path |
| `Auth:LogoutApiUrl` | Logout endpoint path |
| `Auth:AccessTokenStorageKey` | Cookie name for access token |
| `Auth:RefreshTokenStorageKey` | Cookie name for refresh token |
| `Vasp:BaseUrl` | Portal URL for redirects after logout |

### Optional Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `Auth:UserInfoUrl` | (empty) | User profile endpoint URL template |
| `Auth:RefreshTokenRequestUsesGrantType` | `false` | Include grantType field in refresh requests |
| `Auth:RequireAclCheck` | `true` | Enforce ACL gate session check |

## How It Works

### Authentication Flow

1. **User logs in** → Central auth service redirects with `auth-code`
2. **Auth-code exchange** → Your app exchanges code for access + refresh tokens
3. **Token verification** → Tokens are validated and session is established
4. **Protected routes** → Middleware validates token on each request
5. **Automatic refresh** → Expired tokens are refreshed automatically
6. **Logout** → Clears session and cookies, calls auth service logout

### Token Validation

- **Signature**: Validated using RSA public key
- **Issuer**: Must match `Jwt:Issuer` configuration
- **Audience**: Must match `Jwt:Audience` configuration
- **Lifetime**: Validated with zero clock skew
- **Result**: Returns `Valid`, `Expired`, or `Invalid`

### Middleware Behavior

- Skips validation for excluded paths (API routes, auth gate, etc.)
- Reads token from cookie or query string
- Validates token using `ITokenService`
- Automatically refreshes expired tokens using refresh token
- Redirects to session expired page if token is missing or refresh fails

## Security Considerations

- ✅ Zero clock skew for JWT validation
- ✅ RSA signature validation (RS256)
- ✅ Issuer and audience validation
- ✅ Automatic token refresh
- ✅ Secure cookie flags (configurable)
- ✅ SameSite=Lax for CSRF protection
- ⚠️ Requires HTTPS in production
- ⚠️ HttpOnly=false by default (allows JavaScript access)

## Dependencies

- **Microsoft.AspNetCore.App** (8.0+) - Framework reference
- **System.IdentityModel.Tokens.Jwt** (7.0.3+) - JWT parsing and validation
- **Microsoft.AspNetCore.Authentication.JwtBearer** (8.0.0+) - JWT Bearer authentication

## Compatibility

- ✅ .NET 8.0+
- ✅ ASP.NET Core 8.0+
- ✅ C# 12+

### Common Issues

**Token validation fails**
- Verify `Jwt:Issuer` and `Jwt:Audience` match central auth service
- Ensure RSA public key is correct
- Check server clock synchronization

**Middleware not working**
- Verify middleware order: `UseSession` → `UseAuthentication` → `UseAuthorization` → `UseAccessTokenValidation`
- Check excluded paths in middleware

**Token refresh fails**
- Verify `Auth:BaseUrl` and `Auth:RefreshTokenApiUrl` are correct
- Check central auth service is reachable
- Enable debug logging to see detailed errors

### Enable Debug Logging

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "AuthACL.CentralAuth": "Debug"
    }
  }
}
```

---

**Made by AuthACL Team**
