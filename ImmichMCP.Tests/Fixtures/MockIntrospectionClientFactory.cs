using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
using ImmichMCP.Auth;
using ImmichMCP.Configuration;

namespace ImmichMCP.Tests.Fixtures;

public static class MockIntrospectionClientFactory
{
    public static (AutheliaIntrospectionClient Client, MockHttpMessageHandler Handler) CreateMockClient(
        string introspectionUrl = "https://authelia.example.com/api/oidc/introspection",
        string clientId = "immich-mcp",
        string clientSecret = "test-secret",
        string issuer = "https://authelia.example.com",
        string publicUrl = "https://immich-mcp.example.com")
    {
        var mockHandler = new MockHttpMessageHandler();
        var httpClient = mockHandler.ToHttpClient();

        var options = Options.Create(new OidcOptions
        {
            IntrospectionUrl = introspectionUrl,
            ClientId = clientId,
            ClientSecret = clientSecret,
            Issuer = issuer,
            PublicUrl = publicUrl
        });

        var logger = new LoggerFactory().CreateLogger<AutheliaIntrospectionClient>();

        var client = new AutheliaIntrospectionClient(httpClient, options, logger);

        return (client, mockHandler);
    }
}
