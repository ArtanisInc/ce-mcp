using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Symbol management tools for modules, symbols, and address resolution.
    /// </summary>
    [McpServerToolType]
    public class SymbolTool
    {
        private static readonly object SymbolOperationLock = new();
        private static Task? symbolOperationTask;
        private static string? symbolOperationType;
        private static string symbolOperationStatus = "idle";
        private static string? symbolOperationError;
        private static DateTimeOffset? symbolOperationStartedAt;
        private static DateTimeOffset? symbolOperationCompletedAt;

        private SymbolTool() { }

        [McpServerTool(Name = "enum_modules"), Description(
            "Lists all loaded modules (EXEs and DLLs) in the target process, including base addresses, sizes, and paths.")]
        public static object EnumModules()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    var modules = SymbolManager.EnumModules();
                    var result = modules.Select(m => new
                    {
                        name = m.Name,
                        address = $"0x{m.Address:X}",
                        size = m.Size,
                        sizeHex = $"0x{m.Size:X}",
                        is64Bit = m.Is64Bit,
                        path = m.PathToFile
                    }).ToList();

                    return new { success = true, count = result.Count, modules = result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "get_symbol_info"), Description("Retrieves detailed information about a specific symbol (e.g. its module, address, and size).")]
        public static object GetSymbolInfo(
            [Description("Symbol name to look up (e.g. 'kernel32.CreateFileW', 'game.exe+1000')")] string symbolName)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(symbolName))
                        return new { success = false, error = "Symbol name is required" };

                    var info = SymbolManager.GetSymbolInfo(symbolName);
                    if (info == null)
                        return new { success = false, error = $"Symbol not found: {symbolName}" };

                    return new
                    {
                        success = true,
                        moduleName = info.ModuleName,
                        searchKey = info.SearchKey,
                        address = $"0x{info.Address:X}",
                        size = info.Size
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "get_module_size"), Description("Returns the size (in bytes) of a loaded module.")]
        public static object GetModuleSize(
            [Description("Module name (e.g. 'game.exe', 'kernel32.dll')")] string moduleName)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(moduleName))
                        return new { success = false, error = "Module name is required" };

                    var size = SymbolManager.GetModuleSize(moduleName);
                    if (size <= 0)
                    {
                        var module = SymbolManager.EnumModules()
                            .FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase));
                        if (module != null)
                            size = module.Size;
                    }
                    var baseAddr = AddressResolver.GetAddressSafe(moduleName);

                    return new
                    {
                        success = true,
                        module = moduleName,
                        baseAddress = baseAddr.HasValue ? $"0x{baseAddr.Value:X}" : null,
                        size,
                        sizeHex = $"0x{size:X}"
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "enable_symbols"), Description(
            "Enables additional symbol loading features. Non-blocking by default; use get_symbol_loading_status to poll progress.")]
        public static object EnableSymbols(
            [Description("Symbol type to enable: 'windows' or 'kernel'")] string symbolType,
            [Description("If true, waits for the CE Lua call to return. Default false avoids blocking MCP on slow PDB work.")] bool wait = false)
        {
            if (string.IsNullOrWhiteSpace(symbolType))
                return new { success = false, error = "Symbol type is required ('windows' or 'kernel')" };

            var normalizedType = symbolType.Trim().ToLowerInvariant();
            if (normalizedType is not ("windows" or "kernel"))
                return new { success = false, error = $"Unknown symbol type: {symbolType}. Use 'windows' or 'kernel'" };

            if (wait)
            {
                return CeLuaGate.Run<object>(() =>
                {
                    try
                    {
                        EnableSymbolsUnsafe(normalizedType);
                        return new
                        {
                            success = true,
                            started = false,
                            status = "completed",
                            symbolType = normalizedType,
                            symbolsLoaded = SymbolManager.SymbolsDoneLoading(),
                        };
                    }
                    catch (Exception ex)
                    {
                        return new { success = false, error = ex.Message };
                    }
                });
            }

            lock (SymbolOperationLock)
            {
                if (symbolOperationTask is { IsCompleted: false })
                {
                    return new
                    {
                        success = false,
                        error = "A symbol operation is already running",
                        status = symbolOperationStatus,
                        symbolType = symbolOperationType,
                        startedAt = symbolOperationStartedAt,
                    };
                }

                symbolOperationType = normalizedType;
                symbolOperationStatus = "running";
                symbolOperationError = null;
                symbolOperationStartedAt = DateTimeOffset.UtcNow;
                symbolOperationCompletedAt = null;
                symbolOperationTask = Task.Run(() => RunSymbolOperation(normalizedType));
            }

            return new
            {
                success = true,
                started = true,
                status = "running",
                symbolType = normalizedType,
                message = "Symbol loading was started in the background. Poll get_symbol_loading_status.",
            };
        }

        [McpServerTool(Name = "reinitialize_symbols"), Description("Triggers a reinitialization of the symbol handler. Useful after modules are loaded/unloaded.")]
        public static object ReinitializeSymbols(
            [Description("Whether to wait until reinitialization is complete. Default false avoids blocking MCP.")] bool waitTillDone = false)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    SymbolManager.ReinitializeSymbolHandler(waitTillDone);
                    var done = SymbolManager.SymbolsDoneLoading();
                    return new { success = true, symbolsLoaded = done };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "get_symbol_loading_status"), Description("Returns the current symbol loading status without blocking on an active background symbol job.")]
        public static object GetSymbolLoadingStatus()
        {
            Task? currentTask;
            string status;
            string? type;
            string? error;
            DateTimeOffset? startedAt;
            DateTimeOffset? completedAt;

            lock (SymbolOperationLock)
            {
                currentTask = symbolOperationTask;
                status = symbolOperationStatus;
                type = symbolOperationType;
                error = symbolOperationError;
                startedAt = symbolOperationStartedAt;
                completedAt = symbolOperationCompletedAt;
            }

            if (currentTask is { IsCompleted: false })
            {
                return new
                {
                    success = true,
                    status,
                    symbolType = type,
                    startedAt,
                    completedAt,
                    error,
                    symbolsLoaded = false,
                    note = "Background symbol operation is still running; CE/Lua-backed tools may queue behind it.",
                };
            }

            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    return new
                    {
                        success = true,
                        status,
                        symbolType = type,
                        startedAt,
                        completedAt,
                        error,
                        symbolsLoaded = SymbolManager.SymbolsDoneLoading(),
                    };
                }
                catch (Exception ex)
                {
                    return new
                    {
                        success = false,
                        status,
                        symbolType = type,
                        startedAt,
                        completedAt,
                        error = ex.Message,
                    };
                }
            });
        }

        [McpServerTool(Name = "get_pointer_size"), Description("Gets or sets the pointer size (in bytes) that Cheat Engine uses for the target process.")]
        public static object GetOrSetPointerSize(
            [Description("If specified, sets the pointer size (4 or 8). If omitted, returns current size.")] int? newSize = null)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (newSize.HasValue)
                    {
                        SymbolManager.SetPointerSize(newSize.Value);
                        return new { success = true, pointerSize = newSize.Value };
                    }
                    else
                    {
                        var size = SymbolManager.GetPointerSize();
                        return new { success = true, pointerSize = size };
                    }
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static void RunSymbolOperation(string normalizedType)
        {
            try
            {
                CeLuaGate.Run<object>(() =>
                {
                    EnableSymbolsUnsafe(normalizedType);
                    return new { success = true };
                });

                lock (SymbolOperationLock)
                {
                    symbolOperationStatus = "completed";
                    symbolOperationCompletedAt = DateTimeOffset.UtcNow;
                }
            }
            catch (Exception ex)
            {
                lock (SymbolOperationLock)
                {
                    symbolOperationStatus = "failed";
                    symbolOperationError = ex.Message;
                    symbolOperationCompletedAt = DateTimeOffset.UtcNow;
                }
            }
        }

        private static void EnableSymbolsUnsafe(string normalizedType)
        {
            switch (normalizedType)
            {
                case "windows":
                    SymbolManager.EnableWindowsSymbols();
                    break;
                case "kernel":
                    SymbolManager.EnableKernelSymbols();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(normalizedType),
                        normalizedType,
                        "Unknown symbol type"
                    );
            }
        }
    }
}
