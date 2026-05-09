using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace CEMCP.Models
{
    public class ConfigurationModel : INotifyPropertyChanged
    {
        private string _host = "127.0.0.1";
        private int _port = 6300;
        private string _serverName = "Cheat Engine MCP Server";
        private string _authToken = "";
        private bool _allowNonLoopback = false;
        private string _serverStatus = "Stopped";
        private Brush _serverStatusColor = new SolidColorBrush(Color.FromRgb(255, 0, 0));
        private string _testResult = "";
        private bool _isServerRunning = false;
        private bool _isDarkMode = false;

        public string Host
        {
            get => _host;
            set
            {
                if (_host != value)
                {
                    _host = value;
                    OnPropertyChanged();
                    NotifyEndpointPropertiesChanged();
                }
            }
        }

        public int Port
        {
            get => _port;
            set
            {
                if (_port != value)
                {
                    _port = value;
                    OnPropertyChanged();
                    NotifyEndpointPropertiesChanged();
                }
            }
        }

        public string ServerName
        {
            get => _serverName;
            set
            {
                if (_serverName != value)
                {
                    _serverName = value;
                    OnPropertyChanged();
                }
            }
        }

        public string AuthToken
        {
            get => _authToken;
            set
            {
                if (_authToken != value)
                {
                    _authToken = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(AuthHeader));
                    OnPropertyChanged(nameof(SseUrlWithToken));
                }
            }
        }

        public bool AllowNonLoopback
        {
            get => _allowNonLoopback;
            set
            {
                if (_allowNonLoopback != value)
                {
                    _allowNonLoopback = value;
                    OnPropertyChanged();
                }
            }
        }

        public string BaseUrl => $"http://{Host}:{Port}";

        public string SseUrl => $"{BaseUrl}/sse";

        public string SseUrlWithToken =>
            string.IsNullOrWhiteSpace(AuthToken)
                ? SseUrl
                : $"{SseUrl}?token={System.Uri.EscapeDataString(AuthToken.Trim())}";

        public string AuthHeader =>
            string.IsNullOrWhiteSpace(AuthToken)
                ? "Authorization: Bearer <empty>"
                : $"Authorization: Bearer {AuthToken.Trim()}";

        public string StartStopButtonText =>
            ServerStatus.Equals("running", System.StringComparison.CurrentCultureIgnoreCase)
                ? "Stop Server"
                : "Start Server";

        public bool IsServerRunning
        {
            get => _isServerRunning;
            set
            {
                if (_isServerRunning != value)
                {
                    _isServerRunning = value;
                    OnPropertyChanged();
                }
            }
        }

        public bool IsDarkMode
        {
            get => _isDarkMode;
            set
            {
                if (_isDarkMode != value)
                {
                    _isDarkMode = value;
                    OnPropertyChanged();
                    UpdateStatusColor();
                }
            }
        }

        public string ServerStatus
        {
            get => _serverStatus;
            set
            {
                if (_serverStatus != value)
                {
                    _serverStatus = value;
                    OnPropertyChanged();

                    UpdateStatusColor();

                    IsServerRunning = value.Equals(
                        "running",
                        System.StringComparison.CurrentCultureIgnoreCase
                    );
                    OnPropertyChanged(nameof(StartStopButtonText));
                }
            }
        }

        public Brush ServerStatusColor
        {
            get => _serverStatusColor;
            private set
            {
                if (_serverStatusColor != value)
                {
                    _serverStatusColor = value;
                    OnPropertyChanged();
                }
            }
        }

        public string TestResult
        {
            get => _testResult;
            set
            {
                if (_testResult != value)
                {
                    _testResult = value;
                    OnPropertyChanged();
                }
            }
        }

        public void LoadFromServerConfig()
        {
            ServerConfig.EnsureAuthToken();
            Host = ServerConfig.ConfigHost;
            Port = ServerConfig.ConfigPort;
            ServerName = ServerConfig.ConfigServerName;
            AuthToken = ServerConfig.ConfigAuthToken;
            AllowNonLoopback = ServerConfig.ConfigAllowNonLoopback;
        }

        public void SaveToServerConfig()
        {
            ServerConfig.ConfigHost = Host;
            ServerConfig.ConfigPort = Port;
            ServerConfig.ConfigServerName = ServerName;
            ServerConfig.ConfigAllowNonLoopback = AllowNonLoopback;
            ServerConfig.ConfigAuthToken = AuthToken.Trim();
            ServerConfig.EnsureAuthToken();
            AuthToken = ServerConfig.ConfigAuthToken;
            ServerConfig.SaveToFile();
        }

        private void NotifyEndpointPropertiesChanged()
        {
            OnPropertyChanged(nameof(BaseUrl));
            OnPropertyChanged(nameof(SseUrl));
            OnPropertyChanged(nameof(SseUrlWithToken));
        }

        private void UpdateStatusColor()
        {
            string lowerStatus = _serverStatus.ToLower();

            if (lowerStatus == "running")
            {
                // Light green for dark mode, standard green for light mode
                ServerStatusColor = _isDarkMode
                    ? new SolidColorBrush(Color.FromRgb(76, 175, 80))
                    : new SolidColorBrush(Color.FromRgb(0, 128, 0));
            }
            else if (lowerStatus == "stopped")
            {
                // Light red for dark mode, standard red for light mode
                ServerStatusColor = _isDarkMode
                    ? new SolidColorBrush(Color.FromRgb(244, 67, 54))
                    : new SolidColorBrush(Color.FromRgb(255, 0, 0));
            }
            else if (lowerStatus == "starting" || lowerStatus == "stopping")
            {
                // Light orange for dark mode, standard orange for light mode
                ServerStatusColor = _isDarkMode
                    ? new SolidColorBrush(Color.FromRgb(255, 152, 0))
                    : new SolidColorBrush(Color.FromRgb(255, 165, 0));
            }
            else
            {
                // Light gray for dark mode, standard gray for light mode
                ServerStatusColor = _isDarkMode
                    ? new SolidColorBrush(Color.FromRgb(158, 158, 158))
                    : new SolidColorBrush(Color.FromRgb(128, 128, 128));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
