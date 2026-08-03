using System.Net;
using FluentAssertions;
using RichardSzalay.MockHttp;
using ImmichMCP.Tests.Fixtures;

namespace ImmichMCP.Tests.Auth;

public class AutheliaIntrospectionClientTests
{
    [Fact]
    public async Task IsTokenActiveAsync_ActiveTokenResponse_ReturnsTrue()
    {
        var (client, handler) = MockIntrospectionClientFactory.CreateMockClient();
        handler.When(HttpMethod.Post, "https://authelia.example.com/api/oidc/introspection")
            .Respond("application/json", """{"active": true, "sub": "user-1", "scope": "openid profile"}""");

        var active = await client.IsTokenActiveAsync("some.jwt.token", CancellationToken.None);

        active.Should().BeTrue();
    }

    [Fact]
    public async Task IsTokenActiveAsync_InactiveTokenResponse_ReturnsFalse()
    {
        var (client, handler) = MockIntrospectionClientFactory.CreateMockClient();
        handler.When(HttpMethod.Post, "*/introspection")
            .Respond("application/json", """{"active": false}""");

        var active = await client.IsTokenActiveAsync("expired.jwt.token", CancellationToken.None);

        active.Should().BeFalse();
    }

    [Fact]
    public async Task IsTokenActiveAsync_NonSuccessStatusCode_ReturnsFalse()
    {
        var (client, handler) = MockIntrospectionClientFactory.CreateMockClient();
        handler.When(HttpMethod.Post, "*/introspection")
            .Respond(HttpStatusCode.Unauthorized);

        var active = await client.IsTokenActiveAsync("some.jwt.token", CancellationToken.None);

        active.Should().BeFalse();
    }

    [Fact]
    public async Task IsTokenActiveAsync_HttpRequestFails_ReturnsFalse()
    {
        var (client, handler) = MockIntrospectionClientFactory.CreateMockClient();
        handler.When(HttpMethod.Post, "*/introspection")
            .Throw(new HttpRequestException("connection refused"));

        var active = await client.IsTokenActiveAsync("some.jwt.token", CancellationToken.None);

        active.Should().BeFalse();
    }

    [Fact]
    public async Task IsTokenActiveAsync_NotConfigured_ReturnsFalseWithoutCallingIntrospection()
    {
        var (client, handler) = MockIntrospectionClientFactory.CreateMockClient(clientSecret: "");
        var mockedRequest = handler.When(HttpMethod.Post, "*/introspection")
            .Respond("application/json", """{"active": true}""");

        var active = await client.IsTokenActiveAsync("some.jwt.token", CancellationToken.None);

        active.Should().BeFalse();
        handler.GetMatchCount(mockedRequest).Should().Be(0);
    }

    [Fact]
    public async Task IsTokenActiveAsync_SendsClientCredentialsAsBasicAuth()
    {
        var (client, handler) = MockIntrospectionClientFactory.CreateMockClient(clientId: "immich-mcp", clientSecret: "s3cr3t");
        var expectedAuth = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("immich-mcp:s3cr3t"));
        handler.When(HttpMethod.Post, "*/introspection")
            .With(request => request.Headers.Authorization != null
                              && request.Headers.Authorization.Scheme == "Basic"
                              && request.Headers.Authorization.Parameter == expectedAuth)
            .Respond("application/json", """{"active": true}""");

        var active = await client.IsTokenActiveAsync("some.jwt.token", CancellationToken.None);

        active.Should().BeTrue();
    }
}
