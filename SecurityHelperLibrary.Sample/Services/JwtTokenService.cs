using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SecurityHelperLibrary.Sample.Models;

namespace SecurityHelperLibrary.Sample.Services;

public sealed class JwtTokenResult
{
    public string AccessToken { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
    public string Role { get; set; } = string.Empty;
}

public interface IJwtTokenService
{
    JwtTokenResult CreateToken(User user);
}

public sealed class JwtTokenService : IJwtTokenService
{
    private readonly IConfiguration _configuration;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _accessTokenMinutes;
    private readonly HashSet<string> _adminUsers;

    public JwtTokenService(IConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _issuer = configuration["SecurityAudit:Jwt:Issuer"] ?? "SecurityHelperLibrary.Sample";
        _audience = configuration["SecurityAudit:Jwt:Audience"] ?? "SecurityHelperLibrary.Sample.Admin";
        _accessTokenMinutes = configuration.GetValue<int?>("SecurityAudit:Jwt:AccessTokenMinutes") ?? 60;

        var configuredAdmins = configuration.GetSection("SecurityAudit:AdminUsers").Get<string[]>() ?? Array.Empty<string>();
        _adminUsers = new HashSet<string>(configuredAdmins.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);
    }

    public JwtTokenResult CreateToken(User user)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        string role = ResolveRole(user);
        DateTime expiresAtUtc = DateTime.UtcNow.AddMinutes(_accessTokenMinutes);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            claims.Add(new Claim(ClaimTypes.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
        }

        string signingKeyBase64 = _configuration["SecurityAudit:Jwt:SigningKeyBase64"];
        if (string.IsNullOrWhiteSpace(signingKeyBase64) || signingKeyBase64.StartsWith("__SET_VIA_ENV", StringComparison.Ordinal))
            throw new InvalidOperationException("SecurityAudit:Jwt:SigningKeyBase64 must be provided via environment/secret store.");

        byte[] keyBytes;
        try
        {
            keyBytes = Convert.FromBase64String(signingKeyBase64);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("SecurityAudit:Jwt:SigningKeyBase64 must be valid Base64.");
        }

        if (keyBytes.Length < 32)
        {
            SecureZero(keyBytes);
            throw new InvalidOperationException("SecurityAudit:Jwt:SigningKeyBase64 must decode to at least 32 bytes.");
        }

        try
        {
            var credentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: expiresAtUtc,
                signingCredentials: credentials);

            return new JwtTokenResult
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor),
                ExpiresAtUtc = expiresAtUtc,
                Role = role
            };
        }
        finally
        {
            SecureZero(keyBytes);
        }
    }

    private string ResolveRole(User user)
    {
        if (_adminUsers.Contains(user.Username) || _adminUsers.Contains(user.Email))
            return "Admin";

        return "User";
    }

    private static void SecureZero(byte[] data)
    {
        if (data == null || data.Length == 0)
            return;

        CryptographicOperations.ZeroMemory(data);
    }
}
