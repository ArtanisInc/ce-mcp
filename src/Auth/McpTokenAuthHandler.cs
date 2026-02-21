using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CEMCP.Auth
{
    internal static class McpTokenAuthDefaults
    {
        public const string Scheme = "McpToken";
    }

    internal sealed class McpTokenAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public McpTokenAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder
        )
            : base(options, logger, encoder) { }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var expectedToken = ServerConfig.ConfigAuthToken;
            if (string.IsNullOrEmpty(expectedToken))
                return Task.FromResult(
                    AuthenticateResult.Fail("Server auth token is not configured")
                );

            var providedToken = TryGetBearerToken() ?? TryGetHeaderToken() ?? TryGetQueryToken();
            if (string.IsNullOrEmpty(providedToken))
                return Task.FromResult(AuthenticateResult.NoResult());

            if (!FixedTimeEquals(providedToken, expectedToken))
                return Task.FromResult(AuthenticateResult.Fail("Invalid token"));

            var identity = new ClaimsIdentity(McpTokenAuthDefaults.Scheme);
            identity.AddClaim(new Claim(ClaimTypes.Name, "mcp"));
            var principal = new ClaimsPrincipal(identity);

            return Task.FromResult(
                AuthenticateResult.Success(
                    new AuthenticationTicket(principal, McpTokenAuthDefaults.Scheme)
                )
            );
        }

        private string? TryGetBearerToken()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var values))
                return null;

            var header = values.ToString();
            const string prefix = "Bearer ";
            if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return null;

            var token = header[prefix.Length..].Trim();
            return string.IsNullOrEmpty(token) ? null : token;
        }

        private string? TryGetHeaderToken()
        {
            if (!Request.Headers.TryGetValue("X-MCP-Token", out var values))
                return null;
            var token = values.ToString().Trim();
            return string.IsNullOrEmpty(token) ? null : token;
        }

        private string? TryGetQueryToken()
        {
            // Some SSE clients can’t set headers easily.
            var query = Request.Query;
            var token = query["token"].ToString();
            if (string.IsNullOrEmpty(token))
                token = query["access_token"].ToString();
            return string.IsNullOrEmpty(token) ? null : token;
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            var aBytes = Encoding.UTF8.GetBytes(a);
            var bBytes = Encoding.UTF8.GetBytes(b);
            return aBytes.Length == bBytes.Length
                && CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
        }
    }
}
