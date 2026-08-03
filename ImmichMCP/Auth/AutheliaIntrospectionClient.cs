using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using ImmichMCP.Configuration;

namespace ImmichMCP.Auth;

/// <summary>
/// Validates MCP bearer tokens against Authelia's OAuth2 token introspection endpoint (RFC 7662).
/// </summary>
public class AutheliaIntrospectionClient
{
    private readonly HttpClient _http;
    private readonly OidcOptions _options;
    private readonly ILogger<AutheliaIntrospectionClient> _logger;

    public AutheliaIntrospectionClient(HttpClient http, IOptions<OidcOptions> options, ILogger<AutheliaIntrospectionClient> logger)
    {
        _http = http;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<bool> IsTokenActiveAsync(string token, CancellationToken cancellationToken)
    {
        if (!_options.IsConfigured)
        {
            _logger.LogWarning("[auth] OIDC introspection not fully configured (url/client_id/client_secret) - denying bearer token");
            return false;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.IntrospectionUrl)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token })
            };
            var basicAuth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_options.ClientId}:{_options.ClientSecret}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicAuth);

            using var response = await _http.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("[auth] introspection returned HTTP {Status}", (int)response.StatusCode);
                return false;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var active = doc.RootElement.TryGetProperty("active", out var activeProp) && activeProp.ValueKind == JsonValueKind.True;

            if (!active)
            {
                _logger.LogInformation("[auth] introspection: token not active");
            }

            return active;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[auth] introspection request failed");
            return false;
        }
    }
}
