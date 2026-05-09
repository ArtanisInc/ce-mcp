using System;
using System.Threading;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using CEMCP.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CEMCP
{
    public class McpSseServer
    {
        private readonly object _lifecycleLock = new();
        private WebApplication? _app;
        private CancellationTokenSource? _cts;

        public void Start(string baseUrl)
        {
            lock (_lifecycleLock)
            {
                if (_app != null)
                    return; // Already running

                var validatedBaseUrl = ServerConfig.GetValidatedBaseUrl();

                var builder = WebApplication.CreateBuilder(
                    new WebApplicationOptions
                    {
                        Args = [],
                        ContentRootPath = System.IO.Path.GetTempPath(),
                        WebRootPath = System.IO.Path.GetTempPath(),
                    }
                );

                builder
                    .Services.AddAuthentication(McpTokenAuthDefaults.Scheme)
                    .AddScheme<AuthenticationSchemeOptions, McpTokenAuthHandler>(
                        McpTokenAuthDefaults.Scheme,
                        _ => { }
                    );

                builder.Services.AddAuthorization();

                builder.Services.AddRateLimiter(options =>
                {
                    options.RejectionStatusCode = 429;
                    options.AddPolicy(
                        "mcp",
                        httpContext =>
                            RateLimitPartition.GetFixedWindowLimiter(
                                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                                _ => new FixedWindowRateLimiterOptions
                                {
                                    PermitLimit = 60,
                                    Window = TimeSpan.FromSeconds(10),
                                    QueueLimit = 0,
                                }
                            )
                    );
                });

                // Setup MCP server with SSE transport and all tools
                builder
                    .Services.AddMcpServer(options =>
                    {
                        options.ServerInfo = new()
                        {
                            Name = ServerConfig.ConfigServerName,
                            Version =
                                System
                                    .Reflection.Assembly.GetExecutingAssembly()
                                    .GetName()
                                    .Version?.ToString()
                                ?? "1.0.0",
                        };
                    })
                    .WithHttpTransport()
                    .WithTools<Tools.ProcessTool>()
                    .WithTools<Tools.LuaExecutionTool>()
                    .WithTools<Tools.MemoryTool>()
                    .WithTools<Tools.ScanTool>()
                    .WithTools<Tools.AssemblyTool>()
                    .WithTools<Tools.AnalysisTool>()
                    .WithTools<Tools.ConversionTool>()
                    .WithTools<Tools.AddressListTool>()
                    .WithTools<Tools.TraceBreakpointTool>()
                    .WithTools<Tools.MemoryViewTool>()
                    .WithTools<Tools.SymbolTool>()
                    .WithTools<Tools.SpeedhackTool>()
                    .WithResources<Resources.ProcessResources>();

                builder.Logging.ClearProviders(); // Disable logging
                builder.WebHost.UseUrls(validatedBaseUrl);

                // Build app
                _app = builder.Build();

                _app.UseRateLimiter();
                _app.UseAuthentication();
                _app.UseAuthorization();

                // Map MCP endpoints (SSE + Streamable HTTP)
                var mcpEndpoints = _app.MapMcp();
                mcpEndpoints.RequireAuthorization();
                mcpEndpoints.RequireRateLimiting("mcp");

                // Start server
                _cts = new CancellationTokenSource();
                _app.StartAsync(_cts.Token).GetAwaiter().GetResult();
            }
        }

        public void Stop()
        {
            WebApplication? appToStop;
            CancellationTokenSource? ctsToStop;

            lock (_lifecycleLock)
            {
                if (_app == null)
                    return; // Not running

                appToStop = _app;
                ctsToStop = _cts;
                _app = null;
                _cts = null;
            }

            // Stop server in background (don't freeze CE)
            Task.Run(async () =>
            {
                try
                {
                    ctsToStop?.Cancel();
                    await appToStop.StopAsync();
                    await appToStop.DisposeAsync();
                    ctsToStop?.Dispose();
                }
                catch
                {
                    // Best-effort cleanup
                }
            });
        }

        public bool IsRunning => _app != null;
    }
}
