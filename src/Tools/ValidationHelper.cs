using System;
using System.Globalization;
using CESDK.Classes;

namespace Tools
{
    /// <summary>
    /// Shared validation logic for tools.
    /// </summary>
    public static class ValidationHelper
    {
        /// <summary>
        /// Checks if a process is currently attached in Cheat Engine.
        /// </summary>
        public static bool IsProcessAttached()
        {
            int pid = Process.GetOpenedProcessID();
            return pid > 0;
        }

        /// <summary>
        /// Attempts to resolve an address string (hex, decimal, or symbol) to a ulong.
        /// </summary>
        public static bool TryResolveAddress(string address, out ulong result)
        {
            result = 0;
            if (string.IsNullOrWhiteSpace(address))
                return false;

            var trimmed = address.Trim();

            // Handle hex prefix
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ulong.TryParse(
                    trimmed[2..],
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out result
                );
            }

            // Try decimal first
            if (
                ulong.TryParse(
                    trimmed,
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out result
                )
            )
                return true;

            // Try hex without prefix
            if (
                ulong.TryParse(
                    trimmed,
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out result
                )
            )
                return true;

            // Fallback to symbol resolution via CESDK
            try
            {
                var resolved = AddressResolver.GetAddressSafe(trimmed, false);
                if (resolved.HasValue && resolved.Value != 0)
                {
                    result = resolved.Value;
                    return true;
                }
            }
            catch (AddressResolutionException)
            {
                return false;
            }

            return false;
        }
    }
}
