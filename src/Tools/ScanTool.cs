using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;
using static CESDK.CESDK;

namespace Tools
{
    /// <summary>
    /// Memory scanning tools for finding AOB patterns and specific values.
    /// Supports the main Cheat Engine UI scanner and independent background scanners.
    /// </summary>
    [McpServerToolType]
    public class ScanTool
    {
        private ScanTool() { }

        /// <summary>
        /// Independent scanners keyed by user-chosen name. The main UI scanner is not stored here.
        /// </summary>
        private static readonly ConcurrentDictionary<string, MemScan> independentScanners = new(
            StringComparer.OrdinalIgnoreCase
        );

        internal static object CleanupIndependentScannersUnsafe()
        {
            var removed = new List<string>();
            var errors = new List<string>();

            foreach (var kvp in independentScanners)
            {
                if (!independentScanners.TryRemove(kvp.Key, out var scanner))
                    continue;

                removed.Add(kvp.Key);

                try
                {
                    scanner.DeinitializeFoundList();
                    scanner.Dispose();
                }
                catch (Exception ex)
                {
                    errors.Add($"{kvp.Key}: {ex.Message}");
                }
            }

            return new
            {
                removedCount = removed.Count,
                removed,
                errors,
            };
        }

        [
            McpServerTool(Name = "cleanup_independent_scanners"),
            Description(
                "Removes all independent scanners created via 'memory_scan' with a 'scannerName'. Use this to free resources when done."
            )
        ]
        public static object CleanupIndependentScanners()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var result = CleanupIndependentScannersUnsafe();
                    return new { success = true, result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        /// <summary>
        /// Gets the main CE UI scanner (synced with the GUI).
        /// </summary>
        private static MemScan GetMainScanner()
        {
            return MemScan.GetCurrentMemScan();
        }

        /// <summary>
        /// Gets or creates an independent scanner by name.
        /// </summary>
        private static MemScan GetOrCreateIndependentScanner(string name)
        {
            return independentScanners.GetOrAdd(name, _ => new MemScan());
        }

        [McpServerTool(Name = "aob_scan"), Description("Scans memory for an Array of Bytes (AOB) pattern.")]
        public static object AobScan(
            [Description("AOB pattern string (e.g. 'AA BB ?? CC DD')")] string pattern,
            [Description("Protection flags filter (e.g. '+W-C', default: all)")] string protectionFlags = "",
            [Description("Alignment type (e.g. 'fsmAligned', default: none)")] string alignmentType = "",
            [Description("Alignment parameter (e.g. '4' for 4-byte aligned)")] string alignmentParam = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!ValidationHelper.IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };

                try
                {
                    if (string.IsNullOrWhiteSpace(pattern))
                        return new { success = false, error = "AOB pattern is required" };

                    int alignType = 0;
                    if (!string.IsNullOrEmpty(alignmentType))
                    {
                        if (!int.TryParse(alignmentType, out alignType))
                        {
                            if (Enum.TryParse<AlignmentType>(alignmentType, true, out var at))
                            {
                                alignType = (int)at;
                            }
                            else
                            {
                                return new
                                {
                                    success = false,
                                    error = "Invalid alignmentType format (use integer or AlignmentType enum name)",
                                };
                            }
                        }
                    }

                    var result = AobScanner.Scan(
                        pattern,
                        string.IsNullOrEmpty(protectionFlags) ? null : protectionFlags,
                        alignType,
                        string.IsNullOrEmpty(alignmentParam) ? null : alignmentParam
                    );

                    var addresses = result.Select(addr => $"0x{addr:X}").ToList();
                    return new { success = true, addresses };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

#pragma warning disable S107 // Methods should not have too many parameters
        [
            McpServerTool(Name = "memory_scan"),
            Description(
                "Starts a memory scan for a specific value. If 'scannerName' is omitted, uses Cheat Engine's main UI scanner. " +
                "Results are retrieved later using 'get_scan_results'."
            )
        ]
        public static object MemoryScan(
            [Description("Scan condition (e.g. 'soExactValue', 'soIncreasedValue', 'soUnknownValue')")] string scanOption = "soExactValue",
            [Description("Data type to scan for (e.g. 'vtDword', 'vtSingle', 'vtString')")] string varType = "vtDword",
            [Description("Value to find (input1)")] string input1 = "",
            [Description("Secondary value (input2, only for 'soValueBetween')")] string input2 = "",
            [Description("Start address of scan range (default: 0)")] string startAddress = "0",
            [Description("Stop address of scan range (default: max)")] string stopAddress = "FFFFFFFFFFFFFFFF",
            [Description("Protection flags filter (default: '+W-C')")] string protectionFlags = "+W-C",
            [Description("Fast scan alignment (default: 'fsmAligned')")] string alignmentType = "fsmAligned",
            [Description("Alignment parameter (default: '4')")] string alignmentParam = "4",
            [Description("Whether input values are hexadecimal (true/false)")] string isHexadecimalInput = "false",
            [Description("Whether searching for a Unicode string (true/false)")] string isUnicodeScan = "false",
            [Description("Whether the search is case-sensitive (true/false)")] string isCaseSensitive = "false",
            [Description("Whether input is a percentage (true/false)")] string isPercentageScan = "false",
            [Description("Optional name for an independent background scanner")] string scannerName = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!ValidationHelper.IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };

                try
                {
                    bool isMainScanner = string.IsNullOrEmpty(scannerName);

                    if (!Enum.TryParse<ScanOption>(scanOption, true, out var so))
                        return new { success = false, error = $"Invalid scanOption: {scanOption}" };

                    if (!Enum.TryParse<VariableType>(varType, true, out var vt))
                        return new { success = false, error = $"Invalid varType: {varType}" };

                    if (!Enum.TryParse<AlignmentType>(alignmentType, true, out var at))
                        return new
                        {
                            success = false,
                            error = $"Invalid alignmentType: {alignmentType}",
                        };

                    if (!ValidationHelper.TryResolveAddress(startAddress, out var startAddr))
                        return new { success = false, error = "Unable to resolve startAddress" };

                    if (!ValidationHelper.TryResolveAddress(stopAddress, out var stopAddr))
                        return new { success = false, error = "Unable to resolve stopAddress" };

                    if (stopAddr < startAddr)
                        return new
                        {
                            success = false,
                            error = "stopAddress must be >= startAddress",
                        };

                    bool isHex = isHexadecimalInput.Equals(
                        "true",
                        StringComparison.OrdinalIgnoreCase
                    );
                    bool isUnicode = isUnicodeScan.Equals(
                        "true",
                        StringComparison.OrdinalIgnoreCase
                    );
                    bool isCase = isCaseSensitive.Equals(
                        "true",
                        StringComparison.OrdinalIgnoreCase
                    );
                    bool isPercent = isPercentageScan.Equals(
                        "true",
                        StringComparison.OrdinalIgnoreCase
                    );

                    object? earlyResult = null;

                    Action performScan = () =>
                    {
                        MemScan scanner = isMainScanner
                            ? GetMainScanner()
                            : GetOrCreateIndependentScanner(scannerName);

                        // Optimization: Use AOBScanner for first scan with exact value for supported types
                        if (
                            !scanner.HasPreviousScan
                            && so == ScanOption.soExactValue
                            && !isUnicode
                            && !isPercent
                        )
                        {
                            string? aobPattern = ConvertValueToAob(input1, vt, isHex);
                            if (aobPattern != null)
                            {
                                var aobResults = AobScanner.Scan(
                                    aobPattern,
                                    protectionFlags,
                                    (int)at,
                                    alignmentParam
                                );

                                // Respect requested scan range. If nothing is found in range, fall back
                                // to MemScan to keep semantics consistent.
                                var filtered = aobResults
                                    .Where(a => a >= startAddr && a <= stopAddr)
                                    .ToList();

                                var usedProtectionFlags = protectionFlags;
                                if (
                                    filtered.Count == 0
                                    && vt == VariableType.vtByteArray
                                    && protectionFlags == "+W-C"
                                )
                                {
                                    // The memory_scan default targets writable memory. Byte-array
                                    // signatures such as PE headers ("4D 5A") often live in read-only
                                    // image pages, while aob_scan searches more broadly. Retry without
                                    // the default writable-only filter so vtByteArray behaves like AOB.
                                    aobResults = AobScanner.Scan(
                                        aobPattern,
                                        null,
                                        (int)at,
                                        alignmentParam
                                    );
                                    filtered = aobResults
                                        .Where(a => a >= startAddr && a <= stopAddr)
                                        .ToList();
                                    usedProtectionFlags = "";
                                }

                                if (filtered.Count > 0)
                                {
                                    int aobCount = filtered.Count;
                                    var maxAobResults = Math.Min(aobCount, 1000);
                                    var resultsList = new object[maxAobResults];

                                    for (int i = 0; i < maxAobResults; i++)
                                    {
                                        resultsList[i] = new
                                        {
                                            address = $"0x{filtered[i]:X}",
                                            value = input1,
                                        };
                                    }

                                    earlyResult = new
                                    {
                                        success = true,
                                        count = aobCount,
                                        results = resultsList,
                                        syncedWithUI = false,
                                        optimized = true,
                                        aobPattern,
                                        protectionFlags = usedProtectionFlags,
                                        rangeStart = $"0x{startAddr:X}",
                                        rangeStop = $"0x{stopAddr:X}",
                                    };
                                    return;
                                }
                            }
                        }

                        var parameters = new ScanParameters
                        {
                            ScanOption = so,
                            VarType = vt,
                            Input1 = input1,
                            Input2 = input2,
                            StartAddress = startAddr,
                            StopAddress = stopAddr,
                            ProtectionFlags = protectionFlags,
                            AlignmentType = at,
                            AlignmentParam = alignmentParam,
                            IsHexadecimalInput = isHex,
                            IsUnicodeScan = isUnicode,
                            IsCaseSensitive = isCase,
                            IsPercentageScan = isPercent,
                        };

                        // Use the high-level Scan() method which auto-detects first vs next scan
                        scanner.Scan(parameters);
                    };

                    if (isMainScanner)
                    {
                        Synchronize(performScan);
                    }
                    else
                    {
                        performScan();
                    }

                    if (earlyResult != null)
                        return earlyResult;

                    return new
                    {
                        success = true,
                        message = "Scan started in background. Use 'get_scan_results' to retrieve results once complete.",
                        status = "Scanning",
                        syncedWithUI = isMainScanner,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "get_scan_results"),
            Description(
                "Checks the status of a previously started scan and returns the found addresses/values if finished."
            )
        ]
        public static object GetScanResults([Description("Name of the background scanner, or empty for the main UI scanner")] string scannerName = "")
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    bool isMainScanner = string.IsNullOrEmpty(scannerName);
                    MemScan scanner = isMainScanner
                        ? GetMainScanner()
                        : GetOrCreateIndependentScanner(scannerName);

                    if (scanner.Scanning)
                    {
                        return new
                        {
                            success = true,
                            status = "Scanning",
                            progress = scanner.Progress,
                            message = $"Scan is still in progress ({scanner.Progress}%).",
                        };
                    }

                    // Check if this was a region scan (unknown initial value)
                    bool isRegionScan = scanner.LastScanWasRegionScan;

                    if (isRegionScan)
                    {
                        return new
                        {
                            success = true,
                            status = "Finished",
                            isRegionScan = true,
                            message = "Region scan completed. Memory regions marked for next scan. Perform a next scan with a specific condition (e.g., decreased value, exact value) to narrow down results.",
                            syncedWithUI = isMainScanner,
                        };
                    }

                    // Initialize results using the high-level API
                    scanner.InitializeResults();

                    int count = scanner.GetResultCount();
                    if (count == 0)
                        return new
                        {
                            success = true,
                            status = "Finished",
                            count = 0,
                            results = Array.Empty<object>(),
                            syncedWithUI = isMainScanner,
                        };

                    var maxResults = Math.Min(count, 1000);
                    var results = new object[maxResults];

                    for (int i = 0; i < maxResults; i++)
                    {
                        string addrStr = scanner.GetResultAddress(i);
                        if (!TryParseResultAddress(addrStr, out ulong address))
                            throw new FormatException(
                                $"Invalid address format from scan result: {addrStr}"
                            );

                        object value = scanner.GetResultValue(i);
                        results[i] = new { address = $"0x{address:X}", value };
                    }

                    return new
                    {
                        success = true,
                        status = "Finished",
                        count,
                        results,
                        syncedWithUI = isMainScanner,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static bool TryParseResultAddress(string text, out ulong address)
        {
            address = 0;
            if (string.IsNullOrWhiteSpace(text))
                return false;

            var trimmed = text.Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                trimmed = trimmed[2..];

            return ulong.TryParse(
                trimmed,
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture,
                out address
            );
        }
#pragma warning restore S107

        /// <summary>
        /// Converts a value string to an AOB pattern based on the variable type.
        /// </summary>
        private static string? ConvertValueToAob(string value, VariableType varType, bool isHex)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(value))
                    return null;

                switch (varType)
                {
                    case VariableType.vtByte:
                        byte b = isHex ? Convert.ToByte(value, 16) : byte.Parse(value);
                        return b.ToString("X2");

                    case VariableType.vtWord:
                        short s = isHex ? Convert.ToInt16(value, 16) : short.Parse(value);
                        byte[] sBytes = BitConverter.GetBytes(s);
                        return BitConverter.ToString(sBytes).Replace("-", " ");

                    case VariableType.vtDword:
                        int i = isHex ? Convert.ToInt32(value, 16) : int.Parse(value);
                        byte[] iBytes = BitConverter.GetBytes(i);
                        return BitConverter.ToString(iBytes).Replace("-", " ");

                    case VariableType.vtQword:
                        long l = isHex ? Convert.ToInt64(value, 16) : long.Parse(value);
                        byte[] lBytes = BitConverter.GetBytes(l);
                        return BitConverter.ToString(lBytes).Replace("-", " ");

                    case VariableType.vtSingle:
                        float f = float.Parse(value);
                        byte[] fBytes = BitConverter.GetBytes(f);
                        return BitConverter.ToString(fBytes).Replace("-", " ");

                    case VariableType.vtDouble:
                        double d = double.Parse(value);
                        byte[] dBytes = BitConverter.GetBytes(d);
                        return BitConverter.ToString(dBytes).Replace("-", " ");

                    case VariableType.vtByteArray:
                        return NormalizeAobPattern(value);

                    default:
                        return null;
                }
            }
            catch
            {
                return null;
            }
        }

        private static string? NormalizeAobPattern(string value)
        {
            var tokens = value
                .Replace(",", " ", StringComparison.Ordinal)
                .Replace("-", " ", StringComparison.Ordinal)
                .Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);

            if (tokens.Length == 0)
                return null;

            var normalized = new List<string>(tokens.Length);
            foreach (var token in tokens)
            {
                var t = token.Trim();
                if (t == "?" || t == "??" || t.Contains('?'))
                {
                    normalized.Add("??");
                    continue;
                }

                if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    t = t[2..];

                if (t.Length == 1)
                    t = "0" + t;

                if (t.Length != 2 || !byte.TryParse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                    return null;

                normalized.Add(b.ToString("X2", CultureInfo.InvariantCulture));
            }

            return string.Join(" ", normalized);
        }

        [
            McpServerTool(Name = "reset_memory_scan"),
            Description(
                "Resets the scanner state for a fresh search. If 'scannerName' is empty, clears Cheat Engine's main scan results."
            )
        ]
        public static object ResetMemoryScan([Description("Name of the background scanner, or empty for the main UI scanner")] string scannerName = "")
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrEmpty(scannerName))
                    {
                        Synchronize(() =>
                        {
                            MemScan scanner = GetMainScanner();
                            scanner.DeinitializeFoundList();
                            scanner.NewScan();

                            LuaExecutor.Execute(
                                @"
                                local mainForm = getMainForm()
                                if mainForm then
                                    local foundLabel = mainForm.findComponentByName('foundcountlabel')
                                    if foundLabel then
                                        foundLabel.Caption = '0'
                                    end
                                end
                            "
                            );
                        });
                    }
                    else
                    {
                        if (independentScanners.TryRemove(scannerName, out var scanner))
                        {
                            scanner.Dispose();
                        }
                    }

                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }
    }
}
