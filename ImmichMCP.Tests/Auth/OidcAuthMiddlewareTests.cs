using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using RichardSzalay.MockHttp;
using ImmichMCP.Auth;
using ImmichMCP.Tests.Fixtures;

namespace ImmichMCP.Tests.Auth;

public class OidcAuthMiddlewareTests
{
    private static (OidcAuthMiddleware Middleware, MockHttpMessageHandler Handler, Func<bool> NextWasCalled) CreateMiddleware()
    {
        var (introspectionClient, handler) = MockIntrospectionClientFactory.CreateMockClient();
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };
        var logger = new LoggerFactory().CreateLogger<OidcAuthMiddleware>();

        var middleware = new OidcAuthMiddleware(next, introspectionClient, logger);

        return (middleware, handler, () => nextCalled);
    }

    private static DefaultHttpContext CreateContext(string path, string? authorizationHeader = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (authorizationHeader != null)
        {
            context.Request.Headers.Authorization = authorizationHeader;
        }

        return context;
    }

    [Theory]
    [InlineData("/health")]
    [InlineData("/.well-known/oauth-protected-resource")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task InvokeAsync_PublicPath_SkipsAuthAndCallsNext(string path)
    {
        var (middleware, _, nextWasCalled) = CreateMiddleware();
        var context = CreateContext(path);

        await middleware.InvokeAsync(context);

        nextWasCalled().Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task InvokeAsync_NoAuthorizationHeader_Returns401WithoutWwwAuthenticate()
    {
        var (middleware, _, nextWasCalled) = CreateMiddleware();
        var context = CreateContext("/mcp");

        await middleware.InvokeAsync(context);

        nextWasCalled().Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.Should().BeEmpty();
    }

    [Fact]
    public async Task InvokeAsync_NonBearerScheme_Returns401WithWwwAuthenticate()
    {
        var (middleware, _, nextWasCalled) = CreateMiddleware();
        var context = CreateContext("/mcp", "Basic dXNlcjpwYXNz");

        await middleware.InvokeAsync(context);

        nextWasCalled().Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("invalid_token");
    }

    [Fact]
    public async Task InvokeAsync_InactiveToken_Returns401WithWwwAuthenticate()
    {
        var (middleware, handler, nextWasCalled) = CreateMiddleware();
        handler.When(HttpMethod.Post, "*/introspection")
            .Respond("application/json", """{"active": false}""");
        var context = CreateContext("/mcp", "Bearer expired-token");

        await middleware.InvokeAsync(context);

        nextWasCalled().Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().Should().Contain("invalid_token");
    }

    [Fact]
    public async Task InvokeAsync_ActiveToken_CallsNext()
    {
        var (middleware, handler, nextWasCalled) = CreateMiddleware();
        handler.When(HttpMethod.Post, "*/introspection")
            .Respond("application/json", """{"active": true}""");
        var context = CreateContext("/mcp", "Bearer valid-token");

        await middleware.InvokeAsync(context);

        nextWasCalled().Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }
}
