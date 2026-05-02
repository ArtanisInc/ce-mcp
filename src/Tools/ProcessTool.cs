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

        [McpServerTool(Name = "get_module_size"), Description("Returns the memory size (in bytes) of a specific loaded module.")]
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
            Description("Lists all memory regions in the target process, including their protection flags and state.")
        ]
        public static object ListMemoryRegions()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    var regions = ModuleEnumerator
                        .EnumMemoryRegions()
                        .Select(r => new
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

                    return new { success = true, regions };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "reinitialize_symbols"),
            Description("Triggers Cheat Engine to reload and re-parse symbols for the target process.")
        ]
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
