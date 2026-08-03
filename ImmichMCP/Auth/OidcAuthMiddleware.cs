namespace ImmichMCP.Auth;

/// <summary>
/// Gates every request behind a valid Authelia-issued OAuth2 bearer token, except
/// /health and the /.well-known OAuth discovery documents, which stay public so
/// MCP clients (Claude, Cowork) can bootstrap the OAuth flow before they have a token.
/// </summary>
public class OidcAuthMiddleware
{
    private static readonly string[] PublicPathPrefixes = { "/health", "/.well-known" };

    private readonly RequestDelegate _next;
    private readonly AutheliaIntrospectionClient _introspection;
    private readonly ILogger<OidcAuthMiddleware> _logger;

    public OidcAuthMiddleware(RequestDelegate next, AutheliaIntrospectionClient introspection, ILogger<OidcAuthMiddleware> logger)
    {
        _next = next;
        _introspection = introspection;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;

        if (PublicPathPrefixes.Any(prefix => path.StartsWithSegments(prefix)))
        {
            await _next(context);
            return;
        }

        var authHeader = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(authHeader))
        {
            _logger.LogWarning("[auth] {Method} {Path} - deny: no Authorization header", context.Request.Method, path);
            await WriteUnauthorizedAsync(context, includeWwwAuthenticate: false);
            return;
        }

        if (!authHeader.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            _logger.LogWarning("[auth] {Method} {Path} - deny: not a Bearer scheme", context.Request.Method, path);
            await WriteUnauthorizedAsync(context, includeWwwAuthenticate: true);
            return;
        }

        var token = authHeader["Bearer ".Length..];
        var active = await _introspection.IsTokenActiveAsync(token, context.RequestAborted);

        if (!active)
        {
            _logger.LogWarning("[auth] {Method} {Path} - deny: token not active", context.Request.Method, path);
            await WriteUnauthorizedAsync(context, includeWwwAuthenticate: true);
            return;
        }

        await _next(context);
    }

    private static async Task WriteUnauthorizedAsync(HttpContext context, bool includeWwwAuthenticate)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        // With reason="invalid_token" we add an RFC 6750 WWW-Authenticate hint so the
        // OAuth client runs the refresh-token flow. On a missing header we deliberately
        // omit it - sending `Bearer realm="..."` here would short-circuit the client's
        // OAuth discovery instead of letting it start the authorization flow.
        if (includeWwwAuthenticate)
        {
            context.Response.Headers.WWWAuthenticate =
                "Bearer realm=\"immich-mcp\", error=\"invalid_token\", error_description=\"The access token expired or is invalid\"";
        }

        await context.Response.WriteAsync("Unauthorized");
    }
}
