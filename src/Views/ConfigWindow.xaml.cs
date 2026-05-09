using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CEMCP.Models;

namespace CEMCP.Views
{
    public partial class ConfigWindow : Window
    {
        private readonly ConfigurationModel _viewModel;
        private readonly McpPlugin _plugin;

        public ConfigWindow(McpPlugin plugin)
        {
            _plugin = plugin;
            _viewModel = new ConfigurationModel();
            DataContext = _viewModel;

            _viewModel.LoadFromServerConfig();

            bool isDarkMode = ThemeHelper.IsInDarkMode();
            _viewModel.IsDarkMode = isDarkMode;

            InitializeComponent();
            ApplyTheme(isDarkMode);
            UpdateServerStatus();
        }

        private static bool IsServerRunning(McpPlugin? plugin)
        {
            var wrapper = plugin?.GetServerWrapper();
            return wrapper is not null && wrapper.IsRunning;
        }

        private void UpdateServerStatus()
        {
            bool running = IsServerRunning(_plugin);
            _viewModel.ServerStatus = running ? "Running" : "Stopped";
            copySseUrlButton.IsEnabled = running;
            copySseUrlWithTokenButton.IsEnabled = running;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _viewModel.SaveToServerConfig();
                _viewModel.TestResult = "Configuration saved successfully.";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error saving configuration: {ex.Message}";
            }
        }

        private async void TestButton_Click(object sender, RoutedEventArgs e)
        {
            _viewModel.TestResult = "Testing connection...";
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

                if (!string.IsNullOrWhiteSpace(_viewModel.AuthToken))
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                        "Bearer",
                        _viewModel.AuthToken.Trim()
                    );

                var response = await client.GetAsync(
                    $"{_viewModel.BaseUrl}/sse",
                    HttpCompletionOption.ResponseHeadersRead
                );
                _viewModel.TestResult = response.IsSuccessStatusCode
                    ? "✓ Connection successful! MCP SSE Server is responding."
                    : $"✗ Server responded with status: {response.StatusCode}";
            }
            catch (HttpRequestException ex)
            {
                _viewModel.TestResult = $"✗ Connection failed: {ex.Message}";
            }
            catch (TaskCanceledException)
            {
                _viewModel.TestResult = "✗ Connection timed out. Server may not be running.";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"✗ Error testing connection: {ex.Message}";
            }
        }

        private void StartStopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (IsServerRunning(_plugin))
                {
                    _plugin.StopServer();
                    _viewModel.TestResult = "Server stopped.";
                }
                else
                {
                    _viewModel.SaveToServerConfig();
                    _plugin?.StartServer();
                    _viewModel.TestResult = "Server started.";
                }
                UpdateServerStatus();
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error: {ex.Message}";
            }
        }

        private void CopySseUrlButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(_viewModel.SseUrl);
                _viewModel.TestResult = $"Copied to clipboard: {_viewModel.SseUrl}";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error copying URL: {ex.Message}";
            }
        }

        private void CopySseUrlWithTokenButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!EnsureAuthTokenForCopy())
                    return;

                Clipboard.SetText(_viewModel.SseUrlWithToken);
                _viewModel.TestResult = "Copied SSE URL (with token) to clipboard.";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error copying URL: {ex.Message}";
            }
        }

        private void CopyAuthHeaderButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!EnsureAuthTokenForCopy())
                    return;

                Clipboard.SetText(_viewModel.AuthHeader);
                _viewModel.TestResult = "Copied Authorization header to clipboard.";
            }
            catch (Exception ex)
            {
                _viewModel.TestResult = $"Error copying header: {ex.Message}";
            }
        }

        private bool EnsureAuthTokenForCopy()
        {
            if (!string.IsNullOrWhiteSpace(_viewModel.AuthToken))
                return true;

            _viewModel.TestResult = "Auth token is empty. Save configuration to generate a token.";
            return false;
        }

        private void ApplyTheme(bool isDarkMode)
        {
            string prefix = isDarkMode ? "Dark" : "Light";
            var brushes = ResolveThemeBrushes(prefix);

            Background = brushes.Background;
            Resources["BtnHoverBrush"] = brushes.BtnHover;
            Resources["BtnDisabledBgBrush"] = brushes.BtnDisabledBg;
            Resources["BtnDisabledFgBrush"] = brushes.BtnDisabledFg;

            ApplyThemeToElement((DependencyObject)Content, brushes);
        }

        private ThemeBrushes ResolveThemeBrushes(string prefix)
        {
            return new ThemeBrushes
            {
                Background = new SolidColorBrush((Color)FindResource($"{prefix}Bg")),
                Foreground = new SolidColorBrush((Color)FindResource($"{prefix}Fg")),
                TextBoxBg = new SolidColorBrush((Color)FindResource($"{prefix}TextBoxBg")),
                TextBoxBorder = new SolidColorBrush((Color)FindResource($"{prefix}TextBoxBorder")),
                BtnBg = new SolidColorBrush((Color)FindResource($"{prefix}BtnBg")),
                BtnBorder = new SolidColorBrush((Color)FindResource($"{prefix}BtnBorder")),
                BtnHover = new SolidColorBrush((Color)FindResource($"{prefix}BtnHover")),
                BtnDisabledBg = new SolidColorBrush((Color)FindResource($"{prefix}BtnDisabledBg")),
                BtnDisabledFg = new SolidColorBrush((Color)FindResource($"{prefix}BtnDisabledFg")),
            };
        }

        private static void ApplyThemeToElement(DependencyObject element, ThemeBrushes brushes)
        {
            switch (element)
            {
                case TextBlock textBlock:
                    if (textBlock.Name != "statusTextBlock")
                        textBlock.Foreground = brushes.Foreground;
                    break;
                case TextBox textBox:
                    textBox.Background = brushes.TextBoxBg;
                    textBox.Foreground = brushes.Foreground;
                    textBox.BorderBrush = brushes.TextBoxBorder;
                    break;
                case CheckBox checkBox:
                    checkBox.Foreground = brushes.Foreground;
                    break;
                case Button button:
                    button.Background = brushes.BtnBg;
                    button.Foreground = brushes.Foreground;
                    button.BorderBrush = brushes.BtnBorder;
                    break;
                case GroupBox groupBox:
                    groupBox.Foreground = brushes.Foreground;
                    groupBox.BorderBrush = brushes.TextBoxBorder;
                    break;
            }

            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(element); i++)
                ApplyThemeToElement(VisualTreeHelper.GetChild(element, i), brushes);
        }

        private sealed class ThemeBrushes
        {
            public required SolidColorBrush Background { get; init; }
            public required SolidColorBrush Foreground { get; init; }
            public required SolidColorBrush TextBoxBg { get; init; }
            public required SolidColorBrush TextBoxBorder { get; init; }
            public required SolidColorBrush BtnBg { get; init; }
            public required SolidColorBrush BtnBorder { get; init; }
            public required SolidColorBrush BtnHover { get; init; }
            public required SolidColorBrush BtnDisabledBg { get; init; }
            public required SolidColorBrush BtnDisabledFg { get; init; }
        }
    }
}
