using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CEMCP
{
    public static class ServerConfig
    {
        public static string ConfigHost { get; set; } = "127.0.0.1";
        public static int ConfigPort { get; set; } = 6300;
        public static string ConfigBaseUrl
        {
            get
            {
                var host = ConfigHost;
                if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    host = $"[{host}]";
                }
                return $"http://{host}:{ConfigPort}";
            }
        }
        public static string ConfigServerName { get; set; } = "Cheat Engine MCP Server";
        public static string ConfigAuthToken { get; set; } = "";
        public static bool ConfigAllowNonLoopback { get; set; } = false;

        private static string ConfigFilePath =>
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "CeMCP",
                "config.json"
            );

        public static void LoadFromEnvironment()
        {
            var hostEnv = Environment.GetEnvironmentVariable("MCP_HOST");
            if (!string.IsNullOrEmpty(hostEnv))
                ConfigHost = hostEnv;

            var portEnv = Environment.GetEnvironmentVariable("MCP_PORT");
            if (!string.IsNullOrEmpty(portEnv) && int.TryParse(portEnv, out int port))
                ConfigPort = port;

            var tokenEnv = Environment.GetEnvironmentVariable("MCP_AUTH_TOKEN");
            if (!string.IsNullOrEmpty(tokenEnv))
                ConfigAuthToken = tokenEnv;

            var allowNonLoopbackEnv = Environment.GetEnvironmentVariable("MCP_ALLOW_NON_LOOPBACK");
            if (
                !string.IsNullOrEmpty(allowNonLoopbackEnv)
                && bool.TryParse(allowNonLoopbackEnv, out var allowNonLoopback)
            )
                ConfigAllowNonLoopback = allowNonLoopback;
        }

        public static void LoadFromFile()
        {
            try
            {
                if (File.Exists(ConfigFilePath))
                {
                    var json = File.ReadAllText(ConfigFilePath);
                    var config = JsonSerializer.Deserialize<ConfigData>(
                        json,
                        SourceGenerationContext.Default.ConfigData
                    );
                    if (config != null)
                    {
                        ConfigHost = config.Host ?? ConfigHost;
                        ConfigPort = config.Port > 0 ? config.Port : ConfigPort;
                        ConfigServerName = config.ServerName ?? ConfigServerName;
                        ConfigAuthToken = config.AuthToken ?? ConfigAuthToken;
                        ConfigAllowNonLoopback = config.AllowNonLoopback ?? ConfigAllowNonLoopback;
                    }
                }
            }
            catch
            {
                // If loading fails, use defaults.
            }
        }

        public static void SaveToFile()
        {
            var configDir = Path.GetDirectoryName(ConfigFilePath);
            if (configDir != null && !Directory.Exists(configDir))
                Directory.CreateDirectory(configDir);

            var config = new ConfigData
            {
                Host = ConfigHost,
                Port = ConfigPort,
                ServerName = ConfigServerName,
                AuthToken = ConfigAuthToken,
                AllowNonLoopback = ConfigAllowNonLoopback,
            };

            var json = JsonSerializer.Serialize(
                config,
                SourceGenerationContext.Default.ConfigData
            );
            File.WriteAllText(ConfigFilePath, json);
        }

        public static string GetValidatedBaseUrl()
        {
            EnsureAuthToken();

            if (ConfigPort is < 1 or > 65535)
                throw new InvalidOperationException("MCP_PORT must be between 1 and 65535");

            if (!ConfigAllowNonLoopback && !IsLoopbackHost(ConfigHost))
            {
                throw new InvalidOperationException(
                    "Refusing to bind MCP server to a non-loopback host. "
                        + "Set MCP_ALLOW_NON_LOOPBACK=true (and configure MCP_AUTH_TOKEN) to override."
                );
            }

            return ConfigBaseUrl;
        }

        public static void EnsureAuthToken()
        {
            if (!string.IsNullOrEmpty(ConfigAuthToken))
                return;

            ConfigAuthToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            try
            {
                SaveToFile();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Could not save auth token to config file.");
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine(
                    "An MCP auth token was generated in memory but was not printed. "
                        + "Set MCP_AUTH_TOKEN manually or fix the config directory permissions."
                );
            }
        }

        private static bool IsLoopbackHost(string host)
        {
            if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
                return true;

            return IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip);
        }

        internal sealed class ConfigData
        {
            public string? Host { get; set; }
            public int Port { get; set; }
            public string? ServerName { get; set; }
            public string? AuthToken { get; set; }
            public bool? AllowNonLoopback { get; set; }
        }
    }

    // JSON Source Generator for trimming support
    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(ServerConfig.ConfigData))]
    internal partial class SourceGenerationContext : JsonSerializerContext { }
}
