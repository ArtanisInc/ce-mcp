using System;
using System.ComponentModel;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using CESDK.Utils;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Tools for process and module management.
    /// </summary>
    [McpServerToolType]
    public class ProcessTool
    {
        private const int DefaultMemoryRegionLimit = 200;
        private const int MaxMemoryRegionLimit = 1000;

        private ProcessTool() { }

        [
            McpServerTool(Name = "get_process_list"),
            Description("Returns a list of all currently running processes on the system.")
        ]
        public static object GetProcessList()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var processDict = Process.GetProcessList();
                    var processes = processDict
                        .Select(kvp => new { processId = kvp.Key, processName = kvp.Value })
                        .OrderBy(p => p.processName)
                        .ToArray();

                    return new { success = true, processes };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "open_process"), Description("Attaches Cheat Engine to a process by its name or numeric ID.")]
        public static object OpenProcess(
            [Description("Process name (e.g. 'game.exe') or numeric process ID")] string process
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(process))
                        return new { success = false, error = "Process parameter is required" };

                    var processDict = Process.GetProcessList();

                    if (int.TryParse(process, out int pid))
                    {
                        if (pid <= 0)
                            return new
                            {
                                success = false,
                                error = "Process ID must be greater than 0",
                            };

                        if (!processDict.ContainsKey(pid))
                            return new
                            {
                                success = false,
                                error = $"Process with ID {pid} not found",
                            };

                        Process.OpenProcess(pid);
                        return new { success = true };
                    }

                    var target = processDict.FirstOrDefault(p =>
                        string.Equals(p.Value, process, StringComparison.OrdinalIgnoreCase)
                    );

                    if (target.Key == 0)
                        return new
                        {
                            success = false,
                            error = $"Process with name '{process}' not found",
                        };

                    Process.OpenProcess(target.Key);
                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "list_modules"),
            Description("Lists all loaded modules (DLLs/EXEs) for a process.")
        ]
        public static object ListModules([Description("Optional process ID; if omitted, the currently attached process is used")] string? processId = null)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    int? pid = null;
                    if (!string.IsNullOrEmpty(processId))
                    {
                        if (int.TryParse(processId, out var parsedId))
                            pid = parsedId;
                        else
                            return new { success = false, error = "Invalid processId format" };
                    }

                    if (!pid.HasValue)
                    {
                        if (!ValidationHelper.IsProcessAttached())
                            return new { success = false, error = "No process is currently opened. Use openProcess() first." };
                    }

                    var modules = ModuleEnumerator
                        .EnumModules(pid)
                        .Select(m => new
                        {
                            name = m.Name,
                            address = m.Address.ToString("X"),
                            is64Bit = m.Is64Bit,
                        })
                        .ToArray();

                    return new { success = true, modules };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        // Keep this helper for internal/backward-compatible code paths, but expose the
        // public MCP tool only from SymbolTool to avoid duplicate tool names.
        public static object GetModuleSize([Description("Name of the module (e.g. 'kernel32.dll')")] string moduleName)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(moduleName))
                        return new { success = false, error = "moduleName is required" };

                    long size = ModuleEnumerator.GetModuleSize(moduleName);
                    if (size == 0)
                    {
                        var module = ModuleEnumerator.EnumModules()
                            .FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));
                        if (module != null)
                            size = module.Size;
                    }

                    if (size == 0)
                        return new
                        {
                            success = false,
                            error = $"Module '{moduleName}' not found or size is 0",
                        };

                    return new
                    {
                        success = true,
                        size,
                        sizeHex = size.ToString("X"),
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "list_memory_regions"),
            Description(
                "Lists target process memory regions with pagination. Defaults to committed regions and a bounded page to avoid huge MCP responses."
            )
        ]
        public static object ListMemoryRegions(
            [Description("Filter by state: 'committed' (default), 'reserved', 'free', or 'all'")] string filter = "committed",
            [Description("Zero-based page offset after filtering")] int offset = 0,
            [Description("Maximum regions to return. Default 200, max 1000 unless allow_large_result=true")] int limit = DefaultMemoryRegionLimit,
            [Description("Only include regions whose size is at least this many bytes")] ulong min_size = 0,
            [Description("Optional protection filter, e.g. 'execute', 'write', 'readwrite', 'noaccess'")] string? protection = null,
            [Description("If true, returns counts/page metadata without the region list")] bool summary_only = false,
            [Description("Explicitly allow returning every matching region when limit <= 0")] bool allow_large_result = false
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (offset < 0)
                        return new { success = false, error = "offset must be >= 0" };

                    var requestedLimit = NormalizeRegionLimit(limit, allow_large_result);
                    var filtered = ModuleEnumerator
                        .EnumMemoryRegions()
                        .Where(r => MatchesStateFilter(r.State, filter))
                        .Where(r => r.RegionSize >= 0 && (ulong)r.RegionSize >= min_size)
                        .Where(r => MatchesProtectionFilter(r.Protect, protection))
                        .ToList();

                    var total = filtered.Count;
                    var page = requestedLimit.HasValue
                        ? filtered.Skip(offset).Take(requestedLimit.Value).ToList()
                        : filtered.Skip(offset).ToList();

                    var regions = summary_only
                        ? Array.Empty<object>()
                        : page.Select(r => new
                        {
                            baseAddress = r.BaseAddress.ToString("X"),
                            allocationBase = r.AllocationBase.ToString("X"),
                            allocationProtect = r.AllocationProtect,
                            regionSize = r.RegionSize,
                            regionSizeHex = r.RegionSize.ToString("X"),
                            state = r.State,
                            protect = r.Protect,
                            type = r.Type,
                        })
                        .ToArray();

                    var nextOffset = offset + page.Count;
                    return new
                    {
                        success = true,
                        total,
                        count = summary_only ? 0 : regions.Length,
                        offset,
                        limit = requestedLimit,
                        hasMore = nextOffset < total,
                        nextOffset = nextOffset < total ? nextOffset : (int?)null,
                        filter = NormalizeStateFilter(filter),
                        minSize = min_size,
                        protection,
                        summaryOnly = summary_only,
                        regions,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static int? NormalizeRegionLimit(int limit, bool allowLargeResult)
        {
            if (limit <= 0)
                return allowLargeResult ? null : DefaultMemoryRegionLimit;

            return allowLargeResult ? limit : Math.Min(limit, MaxMemoryRegionLimit);
        }

        private static string NormalizeStateFilter(string? filter) =>
            string.IsNullOrWhiteSpace(filter) ? "committed" : filter.Trim().ToLowerInvariant();

        private static bool MatchesStateFilter(int state, string? filter)
        {
            return NormalizeStateFilter(filter) switch
            {
                "all" => true,
                "reserved" => state == 0x2000,
                "free" => state == 0x10000,
                "committed" => state == 0x1000,
                _ => state == 0x1000,
            };
        }

        private static bool MatchesProtectionFilter(int protect, string? protection)
        {
            if (string.IsNullOrWhiteSpace(protection))
                return true;

            var normalized = protection.Trim().ToLowerInvariant().Replace("_", "");
            return normalized switch
            {
                "noaccess" => protect == 0x01,
                "readonly" or "read" => protect is 0x02 or 0x20,
                "readwrite" or "write" => protect is 0x04 or 0x08 or 0x40 or 0x80,
                "execute" => (protect & 0xF0) != 0,
                "executeread" => protect == 0x20,
                "executereadwrite" or "executewrite" => protect == 0x40,
                _ => true,
            };
        }

        // Keep this helper for internal/backward-compatible code paths, but expose the
        // public MCP tool only from SymbolTool to avoid duplicate tool names.
        public static object ReinitializeSymbols([Description("Whether to wait until the symbol handler is fully updated (true/false)")] string waitTillDone = "true")
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    bool wait = waitTillDone.Equals("true", StringComparison.OrdinalIgnoreCase);
                    SymbolHandler.Reinitialize(wait);
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
