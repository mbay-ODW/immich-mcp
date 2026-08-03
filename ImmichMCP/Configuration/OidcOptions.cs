namespace ImmichMCP.Configuration;

/// <summary>
/// Configuration for validating MCP client bearer tokens against an Authelia OIDC provider.
/// </summary>
public class OidcOptions
{
    /// <summary>
    /// RFC 7662 token introspection endpoint (e.g., https://authelia.example.com/api/oidc/introspection).
    /// </summary>
    public string IntrospectionUrl { get; set; } = string.Empty;

    /// <summary>
    /// OIDC client ID registered with Authelia for this MCP server.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// OIDC client secret used for introspection Basic auth.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Authelia issuer base URL (e.g., https://authelia.example.com), used for OAuth discovery.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// This server's own public URL, used in the oauth-protected-resource discovery document.
    /// </summary>
    public string PublicUrl { get; set; } = string.Empty;

    /// <summary>
    /// True when all fields required to introspect a bearer token are set.
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrEmpty(IntrospectionUrl) &&
        !string.IsNullOrEmpty(ClientId) &&
        !string.IsNullOrEmpty(ClientSecret);
}
