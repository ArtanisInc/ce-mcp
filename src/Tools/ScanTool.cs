using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;
using static CESDK.CESDK;

namespace Tools
{
    /// <summary>
    /// Memory scanning tools: AOB pattern scanning and value scanning.
    /// Supports scanning via the main CE GUI scanner (synced with UI) or independent scanners.
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

        /// <summary>
        /// Checks if a process is currently attached in Cheat Engine.
        /// </summary>
        private static bool IsProcessAttached()
        {
            int pid = Process.GetOpenedProcessID();
            return pid > 0;
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

        [McpServerTool(Name = "aob_scan"), Description("Scan memory for an Array of Bytes pattern")]
        public static object AobScan(
            [Description("AOB pattern string (e.g. 'AA BB ?? CC DD')")] string pattern,
            string protectionFlags = "",
            string alignmentType = "",
            string alignmentParam = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!IsProcessAttached())
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
                    if (
                        !string.IsNullOrEmpty(alignmentType)
                        && !int.TryParse(alignmentType, out alignType)
                    )
                        return new { success = false, error = "Invalid alignmentType format" };

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
                "Perform a memory scan for values in the opened process. "
                    + "By default uses the main CE GUI scanner which syncs results with the Cheat Engine UI. "
                    + "Automatically detects first scan vs next scan. Use reset_memory_scan to start fresh."
            )
        ]
        public static object MemoryScan(
            string scanOption = "soExactValue",
            string varType = "vtDword",
            string input1 = "",
            string input2 = "",
            string startAddress = "0",
            string stopAddress = "FFFFFFFFFFFFFFFF",
            string protectionFlags = "+W-C",
            string alignmentType = "fsmAligned",
            string alignmentParam = "4",
            string isHexadecimalInput = "false",
            string isUnicodeScan = "false",
            string isCaseSensitive = "false",
            string isPercentageScan = "false",
            string scannerName = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };

                try
                {
                    bool isMainScanner = string.IsNullOrEmpty(scannerName);
                    MemScan scanner = isMainScanner
                        ? GetMainScanner()
                        : GetOrCreateIndependentScanner(scannerName);

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

                    ulong startAddr = 0;
                    if (
                        !ulong.TryParse(
                            startAddress.Replace("0x", ""),
                            System.Globalization.NumberStyles.HexNumber,
                            null,
                            out startAddr
                        )
                    )
                        return new { success = false, error = "Invalid startAddress format" };

                    ulong stopAddr = ulong.MaxValue;
                    if (
                        !ulong.TryParse(
                            stopAddress.Replace("0x", ""),
                            System.Globalization.NumberStyles.HexNumber,
                            null,
                            out stopAddr
                        )
                    )
                        return new { success = false, error = "Invalid stopAddress format" };

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

                            int aobCount = aobResults.Count;
                            var maxAobResults = Math.Min(aobCount, 1000);
                            var resultsList = new object[maxAobResults];

                            for (int i = 0; i < maxAobResults; i++)
                            {
                                resultsList[i] = new
                                {
                                    address = $"0x{aobResults[i]:X}",
                                    value = input1,
                                };
                            }

                            return new
                            {
                                success = true,
                                count = aobCount,
                                results = resultsList,
                                syncedWithUI = false,
                                optimized = true,
                            };
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
                    scanner.WaitTillDone();

                    // Check if this was a region scan (unknown initial value)
                    bool isRegionScan = scanner.LastScanWasRegionScan;

                    if (isRegionScan)
                    {
                        return new
                        {
                            success = true,
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
                            count = 0,
                            results = Array.Empty<object>(),
                            syncedWithUI = isMainScanner,
                        };

                    var maxResults = Math.Min(count, 1000);
                    var results = new object[maxResults];

                    for (int i = 0; i < maxResults; i++)
                    {
                        string addrStr = scanner.GetResultAddress(i);
                        if (
                            !ulong.TryParse(
                                addrStr.Replace("0x", ""),
                                System.Globalization.NumberStyles.HexNumber,
                                null,
                                out ulong address
                            )
                        )
                            throw new FormatException(
                                $"Invalid address format from scan result: {addrStr}"
                            );

                        object value = scanner.GetResultValue(i);
                        results[i] = new { address = $"0x{address:X}", value };
                    }

                    return new
                    {
                        success = true,
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

                    default:
                        return null;
                }
            }
            catch
            {
                return null;
            }
        }

        [
            McpServerTool(Name = "reset_memory_scan"),
            Description(
                "Reset the memory scan state to start a fresh scan. "
                    + "If no scannerName is provided, resets the main CE GUI scanner. "
                    + "Provide a scannerName to reset a specific independent scanner."
            )
        ]
        public static object ResetMemoryScan(string scannerName = "")
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrEmpty(scannerName))
                    {
                        Synchronize(() =>
                        {
                            var scanner = GetMainScanner();
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
                        independentScanners.TryRemove(scannerName, out _);
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
